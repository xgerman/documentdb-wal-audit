disableTelemetry();

const fs = require('fs');
const assert = require('assert');
const phase = process.env.DEMO_PHASE;
const root = '/artifacts';
const read = name => fs.readFileSync(`${root}/${name}`, 'utf8');
const canonical = value => EJSON.serialize(value, { relaxed: false });

if (phase === 'credentials') {
    print(require('crypto').randomBytes(24).toString('hex'));
} else if (phase === 'ping') {
    assert.strictEqual(db.getSiblingDB('admin').runCommand({ ping: 1 }).ok, 1);
} else if (phase === 'setup') {
    const database = db.getSiblingDB('wal_audit_demo');
    print('db.getSiblingDB("wal_audit_demo").createCollection("documents")');
    assert.strictEqual(database.createCollection('documents').ok, 1);
    assert(database.getCollectionNames().includes('documents'));
    assert(db.getSiblingDB('admin').runCommand({ listDatabases: 1 }).databases
        .some(entry => entry.name === 'wal_audit_demo'));
    print('Database wal_audit_demo created implicitly; collection documents created explicitly.');
} else if (phase === 'workload') {
    const collection = db.getSiblingDB('wal_audit_demo').documents;
    const expected = [];
    const effect = (operation, identifier, before, after) => expected.push({
        operation, objectId: canonical({ _id: identifier }),
        before: canonical(before), after: canonical(after),
    });
    const originals = [
        { _id: 'alpha', message: 'hello WAL', counter: NumberInt(1), enabled: true },
        { _id: 'beta', message: 'replace me', counter: NumberInt(2) },
        { _id: 'gamma', message: 'delete me', counter: NumberInt(3) },
    ];
    const inserted = collection.insertMany(originals);
    assert(inserted.acknowledged && Object.keys(inserted.insertedIds).length === 3);
    for (const document of originals) {
        const actual = collection.findOne({ _id: document._id });
        assert.deepStrictEqual(canonical(actual), canonical(document));
        effect('insert', document._id, null, actual);
    }
    assert.strictEqual(collection.createIndex({ counter: 1 }, { name: 'counter_demo' }), 'counter_demo');
    assert(collection.getIndexes().some(index => index.name === 'counter_demo'));
    let before = collection.findOne({ _id: 'alpha' });
    const updated = collection.updateOne({ _id: 'alpha' }, {
        $set: { message: 'updated through mongosh' }, $inc: { counter: NumberInt(5) },
    });
    assert(updated.acknowledged && updated.matchedCount === 1 && updated.modifiedCount === 1);
    effect('update', 'alpha', before, collection.findOne({ _id: 'alpha' }));
    before = collection.findOne({ _id: 'beta' });
    const replaced = collection.replaceOne({ _id: 'beta' }, {
        _id: 'beta', message: 'replacement document', counter: NumberInt(20),
    });
    assert(replaced.acknowledged && replaced.matchedCount === 1 && replaced.modifiedCount === 1);
    effect('update', 'beta', before, collection.findOne({ _id: 'beta' }));
    before = collection.findOne({ _id: 'gamma' });
    const deleted = collection.deleteOne({ _id: 'gamma' });
    assert(deleted.acknowledged && deleted.deletedCount === 1);
    assert.strictEqual(collection.findOne({ _id: 'gamma' }), null);
    effect('delete', 'gamma', before, null);
    collection.dropIndex('counter_demo');
    assert(!collection.getIndexes().some(index => index.name === 'counter_demo'));
    assert.strictEqual(collection.countDocuments({}), 2);
    fs.writeFileSync(`${root}/expected.json`, JSON.stringify(expected, null, 2) + '\n');
    fs.writeFileSync(`${root}/mongo-state.json`,
        JSON.stringify(canonical(collection.find().sort({ _id: 1 }).toArray())) + '\n');
    print('Acknowledged: 3 inserts, 1 update, 1 replacement, 1 delete; index created/dropped.');
} else if (phase === 'extract') {
    const [, end] = read('range').trim().split(/\s+/);
    const manifest = JSON.parse(read('manifest.json'));
    manifest.validToLsn = end;
    assert.strictEqual(manifest.relations.length, 2);
    assert(manifest.relations.some(relation => relation.kind === 'collections_catalog'));
    assert(manifest.relations.some(relation => relation.kind === 'document'));
    fs.writeFileSync(`${root}/manifest.json`, JSON.stringify(manifest, null, 2) + '\n');
    const size = Number(read('segment-size').trim());
    for (const segment of read('segments').trim().split('\n')) {
        assert(/^[0-9A-F]{24}$/.test(segment));
        const hex = read(`wal/${segment}.hex`).trim();
        assert(/^[0-9a-f]+$/i.test(hex) && hex.length === size * 2);
        fs.writeFileSync(`${root}/wal/${segment}`, Buffer.from(hex, 'hex'), { mode: 0o600 });
        fs.unlinkSync(`${root}/wal/${segment}.hex`);
    }
} else if (phase === 'verify') {
    const expected = JSON.parse(read('expected.json'));
    const events = read('audit.jsonl').trim().split('\n').map(line => JSON.parse(line));
    assert(!events.some(event => event.eventType === 'error'));
    const lsn = value => {
        const [high, low] = value.split('/');
        return (BigInt(`0x${high}`) << 32n) + BigInt(`0x${low}`);
    };
    const [setupStart, setupEnd] = read('setup.range').trim().split(/\s+/).map(lsn);
    const catalogRelations = JSON.parse(read('catalog-relations.json'));
    const creationRecords = events.filter(event => event.eventType === 'postgresRecord'
        && lsn(event.eventLsn) >= setupStart && lsn(event.eventLsn) < setupEnd
        && (event.blocks || []).some(block => catalogRelations.some(relation =>
            ['tblspaceOid', 'databaseOid', 'relfilenode'].every(key => block[key] === relation[key]))));
    assert(creationRecords.length > 0, 'creation phase must expose physical catalog WAL');
    fs.writeFileSync(`${root}/setup-catalog-records.jsonl`,
        creationRecords.map(event => JSON.stringify(event)).join('\n') + '\n');
    assert(!fs.existsSync(`${root}/setup-events.json`),
        'demo-injected lifecycle substitutes are forbidden');
    const lifecycle = events.filter(event => event.eventType === 'catalog'
        && lsn(event.eventLsn) >= setupStart && lsn(event.eventLsn) < setupEnd);
    assert(lifecycle.some(event => event.operation === 'databaseCreate'
        && event.database === 'wal_audit_demo'),
        'WAL-derived databaseCreate is required');
    assert(lifecycle.some(event => event.operation === 'collectionCreate'
        && event.database === 'wal_audit_demo' && event.collection === 'documents'),
        'WAL-derived collectionCreate is required');
    assert(lifecycle.every(event => event.certainty === 'inferred'
        && event.evidence.includes('collections_catalog_insert')
        && !Object.hasOwn(event, 'source')
        && !Object.hasOwn(event, 'originalCommand')));
    fs.writeFileSync(`${root}/setup-lifecycle.json`,
        JSON.stringify(lifecycle, null, 2) + '\n');
    const documents = events.filter(event => event.eventType === 'document');
    assert.strictEqual(documents.length, expected.length);
    const transactions = new Map(events.filter(event => event.eventType === 'transaction')
        .map(event => [event.transactionId, event]));
    const gaps = new Set([
        'tuple bytes are unavailable (including full-page-image-only records)',
        'before document is unavailable in physical WAL',
        'after document is unavailable in physical WAL',
        'before document is unavailable; only replica-identity key is logged',
        'multi-insert tuple bytes unavailable (full-page image is not extracted)',
    ]);
    for (let i = 0; i < documents.length; i++) {
        const actual = documents[i];
        const wanted = expected[i];
        assert.strictEqual(actual.database, 'wal_audit_demo');
        assert.strictEqual(actual.collection, 'documents');
        assert.strictEqual(actual.outcome, 'committed');
        assert.strictEqual(transactions.get(actual.transactionId).outcome, 'committed');
        assert.strictEqual(actual.operation, wanted.operation);
        if (actual.certainty === 'incomplete') {
            assert(actual.warnings.length && actual.warnings.every(warning => gaps.has(warning)));
            assert(['before', 'after'].some(key => wanted[key] !== null && actual[key] === null));
        } else {
            assert.strictEqual(actual.certainty, 'certain');
            assert.deepStrictEqual(actual.warnings, []);
        }
        const updates = documents.filter(event => event.operation === 'update');
        assert.strictEqual(updates.length, 2);
        for (const update of updates) {
            assert.notStrictEqual(update.objectId, null,
                'update/replace objectId must be reconstructed');
            assert.notStrictEqual(update.after, null,
                'update/replace after document must be reconstructed');
            const wanted = expected.find(effect => effect.operation === 'update'
                && effect.objectId._id === update.objectId._id);
            assert(wanted, 'reconstructed update must have a stable objectId');
            assert.deepStrictEqual(update.after, wanted.after,
                'reconstructed update/replace after document must match mongosh');
        }
        for (const key of ['objectId', 'before', 'after']) {
            if (actual[key] === null && wanted[key] !== null) {
                assert.strictEqual(actual.certainty, 'incomplete');
            } else {
                assert.deepStrictEqual(actual[key], wanted[key]);
            }
        }
    }
    assert(documents.some(event => event.operation === 'insert' && event.certainty === 'certain'));
    const complete = documents.filter(event => event.certainty === 'certain').length;
    fs.writeFileSync(`${root}/verification.json`, JSON.stringify({
        expectedEffects: expected.length,
        decodedEffects: documents.length,
        completeEffects: complete,
        incompleteEffects: documents.length - complete,
        physicalCatalogRecords: creationRecords.length,
        lifecycleEvents: lifecycle.length,
        databaseCreate: lifecycle.some(event => event.operation === 'databaseCreate'),
        collectionCreate: lifecycle.some(event => event.operation === 'collectionCreate'),
    }) + '\n');
    print(`PASS: ${documents.length}/${expected.length} Mongo effects matched; ${complete} complete, ${documents.length - complete} explicitly incomplete.`);
    print('Default WAL settings were preserved. Missing images and original commands are not invented.');
} else {
    throw new Error(`Unknown DEMO_PHASE: ${phase}`);
}
