//! Metric sink — CONTRACTS §14 (metric-name taxonomy) and §6.1 (the
//! `metrics` lifecycle: 3600 s buckets, born `collecting`, `bucket_current`
//! counts seconds accumulated in the open bucket, rolls to `queued` when the
//! bucket ages out, then `sent` like the rest of the outbox).
//!
//! JSON shapes are verbatim from the captured `metrics` sample rows
//! (`local-db.md` §Evidence):
//! * `bucket_id` — JSON array of indexed dimension tags
//!   (`{"indexed":bool,"name":…,"value":…}`);
//! * `tags` — parallel array with explicit aggregation annotations
//!   (`{"aggregation":"INDEXED"|"CARDINAL"|"INCIDENTAL","name":…,"value":…}`);
//! * `fields` — measured values (`{"name":…,"operation":u8,"value":…}`).

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::{mark_ids_sent, Outbox};
use crate::CoreError;

/// Bucket size in seconds (§6.1: `bucket_size = 3600`, one hour).
pub const BUCKET_SIZE_SECS: i64 = 3600;

/// The only `operation` code observed in CE's captured rows
/// (`local-db.md` §Evidence: `startup_count` with `operation: 4`; the code
/// table itself is an open question there). Equal `(name, operation)` field
/// pairs accumulate by numeric sum within a bucket — the semantics CE's
/// rollup implies for a counter.
pub const OPERATION_AGGREGATE: u8 = 4;

/// Metric names of CONTRACTS §14 (CE taxonomy kept from the `local-db.md`
/// sample rows).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricName {
    /// `client_startup` — daemon/client start events (§14).
    ClientStartup,
    /// `client_api_success` — successful API call, tagged with
    /// host/route/status (§10/§14).
    ClientApiSuccess,
    /// `client_api_problem` — failed API call (§10/§14).
    ClientApiProblem,
    /// `client_network` — network health samples (§14).
    ClientNetwork,
    /// `client_screenshot` — capture-path counter (§14).
    ClientScreenshot,
    /// `client_cleanbrowsing_success` — healthy filter-path lookups (§8/§14).
    ClientCleanbrowsingSuccess,
    /// `client_cleanbrowsing_problem` — filter-path failures feeding the
    /// health machine (§8/§14).
    ClientCleanbrowsingProblem,
    /// `client_crash` — recovered crash counter (§11/§14).
    ClientCrash,
    /// `collect_diagnostics_in_progress` — diagnostics-collection trigger
    /// (§5 code 0x43, §14).
    CollectDiagnosticsInProgress,
}

impl MetricName {
    /// Every §14 metric name, in contract order.
    pub const ALL: [MetricName; 9] = [
        MetricName::ClientStartup,
        MetricName::ClientApiSuccess,
        MetricName::ClientApiProblem,
        MetricName::ClientNetwork,
        MetricName::ClientScreenshot,
        MetricName::ClientCleanbrowsingSuccess,
        MetricName::ClientCleanbrowsingProblem,
        MetricName::ClientCrash,
        MetricName::CollectDiagnosticsInProgress,
    ];

    /// The verbatim metric name stored in `metrics.metric_name` (§14).
    pub const fn as_str(self) -> &'static str {
        match self {
            MetricName::ClientStartup => "client_startup",
            MetricName::ClientApiSuccess => "client_api_success",
            MetricName::ClientApiProblem => "client_api_problem",
            MetricName::ClientNetwork => "client_network",
            MetricName::ClientScreenshot => "client_screenshot",
            MetricName::ClientCleanbrowsingSuccess => "client_cleanbrowsing_success",
            MetricName::ClientCleanbrowsingProblem => "client_cleanbrowsing_problem",
            MetricName::ClientCrash => "client_crash",
            MetricName::CollectDiagnosticsInProgress => "collect_diagnostics_in_progress",
        }
    }
}

/// One `bucket_id` entry — an indexed dimension tag
/// (`{"indexed":bool,"name":…,"value":…}`, verbatim sample-row shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketTag {
    /// `true` when the dimension is indexed for querying (sample rows).
    pub indexed: bool,
    /// Dimension name (e.g. `client_component`, `os_name`).
    pub name: String,
    /// Dimension value (rendered as a string, per the sample rows).
    pub value: String,
}

/// Aggregation annotation of a `tags` entry — `INDEXED` / `CARDINAL` /
/// `INCIDENTAL` (§6.1, verbatim from the sample rows).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Aggregation {
    /// Indexed dimension (e.g. `client_component`, `ce_cluster`).
    Indexed,
    /// Cardinality-tracked dimension.
    Cardinal,
    /// Carried along for context only (e.g. `bucket_size`).
    Incidental,
}

/// One `tags` entry — parallel to `bucket_id` with the aggregation
/// annotation (`{"aggregation":…,"name":…,"value":…}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggTag {
    /// Aggregation semantics (§6.1).
    pub aggregation: Aggregation,
    /// Tag name.
    pub name: String,
    /// Tag value (string, per the sample rows).
    pub value: String,
}

/// One `fields` entry — a measured value
/// (`{"name":…,"operation":u8,"value":…}`, verbatim sample-row shape).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricField {
    /// Field name (e.g. `api_count`, `startup_count`).
    pub name: String,
    /// Operation code (see [`OPERATION_AGGREGATE`]).
    pub operation: u8,
    /// Measured value.
    pub value: Value,
}

/// A queued `metrics` row ready for `POST /v1/metrics` (§10), with the JSON
/// columns parsed back into their typed shapes.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricRow {
    /// Row id.
    pub id: i64,
    /// Account username.
    pub username: String,
    /// Metric name (§14).
    pub metric_name: String,
    /// Indexed dimension tags of the bucket.
    pub bucket_id: Vec<BucketTag>,
    /// Aggregation-annotated tags.
    pub tags: Vec<AggTag>,
    /// Accumulated fields.
    pub fields: Vec<MetricField>,
    /// Bucket anchor timestamp, ISO-8601 UTC.
    pub utc_timestamp: String,
    /// Bucket size in seconds (3600, §6.1).
    pub bucket_size: i64,
    /// Seconds accumulated in the open bucket (3600 = complete, §6.1).
    pub bucket_current: i64,
    /// Row status (`collecting`/`queued`/`sent`, §6.1).
    pub status: String,
    /// Status change stamp (SQLite `DATETIME('now')` format).
    pub status_changed_at: String,
    /// Row creation stamp (SQLite `DATETIME('now')` format).
    pub created_at: String,
}

/// Accumulates metrics into the `metrics` table of the outbox (§6.1/§14).
///
/// One [`MetricSink`] borrows the [`Outbox`] mutably; drop it before handing
/// the outbox back to the event-table writers.
pub struct MetricSink<'a> {
    outbox: &'a mut Outbox,
}

impl<'a> MetricSink<'a> {
    /// Creates a sink over the outbox.
    pub fn new(outbox: &'a mut Outbox) -> Self {
        MetricSink { outbox }
    }

    /// Records one sample into the open bucket of
    /// `(username, metric, bucket_id)`:
    ///
    /// * aged-out open buckets are rolled to `queued` first (§6.1);
    /// * an open `collecting` bucket is updated with the evidence SQL shape
    ///   (`fields`, `utc_timestamp`, `bucket_current = UNIXEPOCH(now) −
    ///   UNIXEPOCH(created_at)` — `upload-protocol.md` §4); equal
    ///   `(name, operation)` fields sum up;
    /// * otherwise a fresh row is inserted born `status='collecting'`,
    ///   `bucket_size=3600`, `bucket_current=0` (§6.1 sample rows).
    ///
    /// `tags`/`bucket_id` are fixed at insert time (the evidence UPDATE only
    /// touches `fields`/`utc_timestamp`/`bucket_current`).
    pub fn record(
        &mut self,
        username: &str,
        metric: MetricName,
        bucket_id: &[BucketTag],
        tags: &[AggTag],
        fields: &[MetricField],
    ) -> Result<(), CoreError> {
        self.roll_ready()?;
        let bucket_json = serde_json::to_string(bucket_id)?;
        let conn = self.outbox.conn_mut();

        let open: Option<(String, String)> = conn
            .query_row(
                "SELECT fields, utc_timestamp FROM metrics \
                 WHERE username = ?1 AND metric_name = ?2 AND bucket_id = ?3 \
                 AND status = 'collecting'",
                params![username, metric.as_str(), bucket_json],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        match open {
            Some((existing_fields, utc_timestamp)) => {
                let merged = merge_fields(&existing_fields, fields)?;
                conn.execute(
                    "UPDATE metrics SET fields = ?1, utc_timestamp = ?2, \
                     bucket_current = (UNIXEPOCH(DATETIME('now')) - UNIXEPOCH(created_at)) \
                     WHERE username = ?3 AND metric_name = ?4 AND bucket_id = ?5 \
                     AND status = 'collecting'",
                    params![
                        merged,
                        utc_timestamp,
                        username,
                        metric.as_str(),
                        bucket_json
                    ],
                )?;
            }
            None => {
                let utc_timestamp = crate::db::iso_now(conn)?;
                let tags_json = serde_json::to_string(tags)?;
                let fields_json = serde_json::to_string(fields)?;
                conn.execute(
                    "INSERT INTO metrics (username, metric_name, bucket_id, tags, fields, utc_timestamp, bucket_size, bucket_current, status, status_changed_at, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 'collecting', DATETIME('now'), DATETIME('now'))",
                    params![
                        username,
                        metric.as_str(),
                        bucket_json,
                        tags_json,
                        fields_json,
                        utc_timestamp,
                        BUCKET_SIZE_SECS,
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Rolls every `collecting` bucket older than [`BUCKET_SIZE_SECS`] to
    /// `queued` (§6.1, evidence `upload-protocol.md` §4:
    /// `… WHERE status = 'collecting' AND (UNIXEPOCH(DATETIME('now')) -
    /// UNIXEPOCH(created_at)) >= ?`). Returns the number of rolled rows.
    pub fn roll_ready(&mut self) -> Result<usize, CoreError> {
        Ok(self.outbox.conn_mut().execute(
            "UPDATE metrics SET status = 'queued', status_changed_at = DATETIME('now') \
             WHERE status = 'collecting' \
             AND (UNIXEPOCH(DATETIME('now')) - UNIXEPOCH(created_at)) >= ?1",
            params![BUCKET_SIZE_SECS],
        )?)
    }

    /// Reads `queued` buckets oldest-first for `POST /v1/metrics` (§10).
    /// Metrics go `queued → sent` directly — CE's captured rows never use a
    /// `sending` state for `metrics` (`local-db.md` §Evidence;
    /// `upload-protocol.md` §4 "select-by-key then sent").
    pub fn queued(&self, limit: u32) -> Result<Vec<MetricRow>, CoreError> {
        let mut stmt = self.outbox.conn().prepare(
            "SELECT id, username, metric_name, bucket_id, tags, fields, utc_timestamp, \
                    bucket_size, bucket_current, status, status_changed_at, created_at \
             FROM metrics WHERE status = 'queued' ORDER BY id LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], map_metric_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Acks uploaded buckets: `queued → sent` (§6.1). Returns the number of
    /// rows updated.
    pub fn mark_sent(&mut self, ids: &[i64]) -> Result<usize, CoreError> {
        mark_ids_sent(self.outbox.conn(), "metrics", ids)
    }
}

/// Merges incoming fields into the open bucket's `fields` JSON: equal
/// `(name, operation)` entries sum when both values are numeric (see
/// [`OPERATION_AGGREGATE`]), otherwise the incoming value replaces or appends.
fn merge_fields(existing: &str, incoming: &[MetricField]) -> Result<String, CoreError> {
    let mut merged: Vec<MetricField> = serde_json::from_str(existing)?;
    for field in incoming {
        match merged
            .iter_mut()
            .find(|entry| entry.name == field.name && entry.operation == field.operation)
        {
            Some(entry) => match (&mut entry.value, &field.value) {
                (Value::Number(before), Value::Number(after)) => {
                    let sum = match (before.as_i64(), after.as_i64()) {
                        (Some(before), Some(after)) => Value::from(before + after),
                        _ => Value::from(
                            before.as_f64().unwrap_or(0.0) + after.as_f64().unwrap_or(0.0),
                        ),
                    };
                    entry.value = sum;
                }
                _ => entry.value = field.value.clone(),
            },
            None => merged.push(field.clone()),
        }
    }
    Ok(serde_json::to_string(&merged)?)
}

/// Maps one `metrics` row (column order of the §6.1 schema) into a typed
/// [`MetricRow`].
fn map_metric_row(row: &rusqlite::Row<'_>) -> Result<MetricRow, rusqlite::Error> {
    /// Parses one JSON column (indices match the §6.1 `metrics` schema).
    fn parse_json<T: serde::de::DeserializeOwned>(
        index: usize,
        raw: &str,
    ) -> Result<T, rusqlite::Error> {
        serde_json::from_str(raw).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(err),
            )
        })
    }

    let bucket_id: String = row.get(3)?;
    let tags: String = row.get(4)?;
    let fields: String = row.get(5)?;
    Ok(MetricRow {
        id: row.get(0)?,
        username: row.get(1)?,
        metric_name: row.get(2)?,
        bucket_id: parse_json(3, &bucket_id)?,
        tags: parse_json(4, &tags)?,
        fields: parse_json(5, &fields)?,
        utc_timestamp: row.get(6)?,
        bucket_size: row.get(7)?,
        bucket_current: row.get(8)?,
        status: row.get(9)?,
        status_changed_at: row.get(10)?,
        created_at: row.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::EventTable;
    use crate::test_util::TempDir;
    use serde_json::json;

    fn open(tag: &str) -> (TempDir, Outbox) {
        let dir = TempDir::new(tag);
        let outbox = Outbox::open(&dir.path().join("outbox.db")).expect("open outbox");
        (dir, outbox)
    }

    fn bucket_tags() -> Vec<BucketTag> {
        vec![
            BucketTag {
                indexed: true,
                name: "client_component".into(),
                value: "service".into(),
            },
            BucketTag {
                indexed: false,
                name: "device_id".into(),
                value: "0123456789abcdef0123456789abcdef".into(),
            },
        ]
    }

    fn agg_tags() -> Vec<AggTag> {
        vec![
            AggTag {
                aggregation: Aggregation::Incidental,
                name: "bucket_size".into(),
                value: "3600".into(),
            },
            AggTag {
                aggregation: Aggregation::Indexed,
                name: "client_version".into(),
                value: "0.1.0".into(),
            },
        ]
    }

    fn counter(value: i64) -> Vec<MetricField> {
        vec![MetricField {
            name: "api_count".into(),
            operation: OPERATION_AGGREGATE,
            value: Value::from(value),
        }]
    }

    fn raw_row(sink: &MetricSink<'_>) -> (String, i64, i64, String, String, String, String) {
        sink.outbox
            .conn()
            .query_row(
                "SELECT status, bucket_size, bucket_current, bucket_id, tags, fields, utc_timestamp \
                 FROM metrics ORDER BY id",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .expect("one metrics row")
    }

    fn row_count(sink: &MetricSink<'_>) -> i64 {
        sink.outbox
            .conn()
            .query_row("SELECT COUNT(*) FROM metrics", [], |row| row.get(0))
            .expect("count")
    }

    #[test]
    fn metric_names_match_contract_section_14() {
        let expected = [
            "client_startup",
            "client_api_success",
            "client_api_problem",
            "client_network",
            "client_screenshot",
            "client_cleanbrowsing_success",
            "client_cleanbrowsing_problem",
            "client_crash",
            "collect_diagnostics_in_progress",
        ];
        let names: Vec<&str> = MetricName::ALL.iter().map(|name| name.as_str()).collect();
        assert_eq!(names, expected.to_vec());
    }

    #[test]
    fn record_opens_a_collecting_bucket_with_verbatim_json_shapes() {
        let (_dir, mut outbox) = open("metrics-record");
        let mut sink = MetricSink::new(&mut outbox);

        sink.record(
            "alice",
            MetricName::ClientApiSuccess,
            &bucket_tags(),
            &agg_tags(),
            &counter(1),
        )
        .expect("record");

        let (status, bucket_size, bucket_current, bucket_id, tags, fields, utc) = raw_row(&sink);
        assert_eq!(status, "collecting", "§6.1: born collecting");
        assert_eq!(bucket_size, 3600, "§6.1: bucket_size=3600");
        assert_eq!(bucket_current, 0, "§6.1: 0 = just opened");
        assert!(utc.ends_with('Z'), "ISO-8601 UTC: {utc}");
        assert_eq!(utc.len(), 20);

        // Shapes verbatim from the local-db.md sample rows.
        assert_eq!(
            serde_json::from_str::<Value>(&bucket_id).expect("bucket_id JSON"),
            json!([
                {"indexed": true, "name": "client_component", "value": "service"},
                {"indexed": false, "name": "device_id",
                 "value": "0123456789abcdef0123456789abcdef"},
            ])
        );
        assert_eq!(
            serde_json::from_str::<Value>(&tags).expect("tags JSON"),
            json!([
                {"aggregation": "INCIDENTAL", "name": "bucket_size", "value": "3600"},
                {"aggregation": "INDEXED", "name": "client_version", "value": "0.1.0"},
            ])
        );
        assert_eq!(
            serde_json::from_str::<Value>(&fields).expect("fields JSON"),
            json!([{"name": "api_count", "operation": 4, "value": 1}])
        );
    }

    #[test]
    fn record_accumulates_into_the_open_bucket() {
        let (_dir, mut outbox) = open("metrics-accumulate");
        let mut sink = MetricSink::new(&mut outbox);

        sink.record(
            "alice",
            MetricName::ClientApiSuccess,
            &bucket_tags(),
            &agg_tags(),
            &counter(1),
        )
        .unwrap();
        sink.record(
            "alice",
            MetricName::ClientApiSuccess,
            &bucket_tags(),
            &agg_tags(),
            &counter(2),
        )
        .unwrap();

        // Still one open bucket…
        assert_eq!(row_count(&sink), 1);
        let (status, _, bucket_current, _, _, fields, _) = raw_row(&sink);
        assert_eq!(status, "collecting");
        assert!(bucket_current >= 0, "bucket_current counts elapsed seconds");

        // …and equal (name, operation) fields summed: 1 + 2 = 3.
        assert_eq!(
            serde_json::from_str::<Value>(&fields).expect("fields JSON"),
            json!([{"name": "api_count", "operation": 4, "value": 3}])
        );
    }

    #[test]
    fn aged_buckets_roll_to_queued_then_ack_sent() {
        let (_dir, mut outbox) = open("metrics-roll");
        let mut sink = MetricSink::new(&mut outbox);

        sink.record(
            "alice",
            MetricName::ClientStartup,
            &bucket_tags(),
            &agg_tags(),
            &[MetricField {
                name: "startup_count".into(),
                operation: OPERATION_AGGREGATE,
                value: Value::from(1),
            }],
        )
        .unwrap();

        // A young bucket does not roll.
        assert_eq!(sink.roll_ready().unwrap(), 0);

        // Age the open bucket past 3600 s (§6.1) and roll.
        sink.outbox
            .conn()
            .execute(
                "UPDATE metrics SET created_at = DATETIME('now', '-3700 seconds')",
                [],
            )
            .unwrap();
        assert_eq!(sink.roll_ready().unwrap(), 1);

        // Queued rows read back typed…
        let queued = sink.queued(10).expect("queued");
        assert_eq!(queued.len(), 1);
        let row = &queued[0];
        assert_eq!(row.username, "alice");
        assert_eq!(row.metric_name, "client_startup");
        assert_eq!(row.bucket_size, 3600);
        assert_eq!(row.bucket_id, bucket_tags());
        assert_eq!(row.tags, agg_tags());
        assert_eq!(row.fields[0].name, "startup_count");

        // …and ack to 'sent' (metrics skip 'sending', §6.1 evidence).
        assert_eq!(sink.mark_sent(&[row.id]).unwrap(), 1);
        assert_eq!(sink.queued(10).unwrap().len(), 0);
        let status: String = sink
            .outbox
            .conn()
            .query_row("SELECT status FROM metrics", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "sent");
    }

    #[test]
    fn record_after_roll_opens_a_fresh_bucket() {
        let (_dir, mut outbox) = open("metrics-fresh");
        let mut sink = MetricSink::new(&mut outbox);

        sink.record(
            "alice",
            MetricName::ClientNetwork,
            &bucket_tags(),
            &agg_tags(),
            &counter(5),
        )
        .unwrap();
        sink.outbox
            .conn()
            .execute(
                "UPDATE metrics SET created_at = DATETIME('now', '-3700 seconds')",
                [],
            )
            .unwrap();

        // The next record rolls the old bucket and opens a new one.
        sink.record(
            "alice",
            MetricName::ClientNetwork,
            &bucket_tags(),
            &agg_tags(),
            &counter(7),
        )
        .unwrap();

        assert_eq!(row_count(&sink), 2, "one queued + one collecting");
        let mut stmt = sink
            .outbox
            .conn()
            .prepare("SELECT status, bucket_current FROM metrics ORDER BY id")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        let first = rows.next().unwrap().expect("first row");
        assert_eq!(first.get::<_, String>(0).unwrap(), "queued");
        let second = rows.next().unwrap().expect("second row");
        assert_eq!(second.get::<_, String>(0).unwrap(), "collecting");
        assert_eq!(second.get::<_, i64>(1).unwrap(), 0, "fresh bucket");
        assert!(rows.next().unwrap().is_none());

        // A roll does not touch event tables (§6.1 lifecycles are separate).
        let event_rows: i64 = sink
            .outbox
            .conn()
            .query_row("SELECT COUNT(*) FROM dns_activity", [], |row| row.get(0))
            .unwrap();
        assert_eq!(event_rows, 0);
        assert_ne!(
            EventTable::Telemetry.as_str(),
            "metrics",
            "metrics is not an event table"
        );
    }

    #[test]
    fn aggregation_serializes_uppercase() {
        assert_eq!(
            serde_json::to_value(Aggregation::Indexed).unwrap(),
            json!("INDEXED")
        );
        assert_eq!(
            serde_json::to_value(Aggregation::Cardinal).unwrap(),
            json!("CARDINAL")
        );
        assert_eq!(
            serde_json::to_value(Aggregation::Incidental).unwrap(),
            json!("INCIDENTAL")
        );
    }
}
