// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use super::{PgmonetaHandler, hints};
use crate::client::PgmonetaClient;
use anyhow::{Result, anyhow, bail};
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::{JsonObject, ToolAnnotations};
use rmcp::schemars;
use serde_json::Value;

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct MetricsRequest {
    pub username: String,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct MetricRequest {
    pub username: String,
    pub name: String,
    #[serde(default)]
    pub attributes: HashMap<String, Value>,
    #[serde(default)]
    pub labels: HashMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetricQuery {
    name: String,
    attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetricSample {
    name: String,
    attributes: HashMap<String, String>,
    line: String,
    value: String,
}

/// Tool for fetching the complete pgmoneta Prometheus metrics exposition.
pub struct GetMetricsTool;

impl ToolBase for GetMetricsTool {
    type Parameter = MetricsRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "get_metrics".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::read_only())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Fetch all Prometheus metrics exposed by pgmoneta from the configured metrics endpoint. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for GetMetricsTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: MetricsRequest,
    ) -> Result<String, McpError> {
        PgmonetaClient::request_metrics(&request.username)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to fetch metrics: {:?}", e), None)
            })
    }
}

/// Tool for fetching a single pgmoneta Prometheus metric value.
pub struct MetricTool;

impl ToolBase for MetricTool {
    type Parameter = MetricRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "metric".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::read_only())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Fetch a single Prometheus metric value exposed by pgmoneta using a metric name and optional attributes. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for MetricTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: MetricRequest,
    ) -> Result<String, McpError> {
        let query = normalize_metric_request(request)
            .map_err(|e| McpError::invalid_params(format!("Invalid metric request: {e}"), None))?;

        let metrics = PgmonetaClient::request_metrics(&query.username)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to fetch metrics: {:?}", e), None)
            })?;

        find_metric_value(&metrics, &query.metric).map_err(|e| {
            McpError::internal_error(format!("Failed to resolve metric value: {e}"), None)
        })
    }
}

#[derive(Debug)]
struct NormalizedMetricQuery {
    username: String,
    metric: MetricQuery,
}

fn normalize_metric_request(request: MetricRequest) -> Result<NormalizedMetricQuery> {
    let name = request.name.trim();
    if name.is_empty() {
        bail!("Metric request requires a non-empty 'name' field");
    }

    if !request.attributes.is_empty() && !request.labels.is_empty() {
        bail!("Metric request can define either 'attributes' or 'labels', not both");
    }

    let attributes = if !request.attributes.is_empty() {
        parse_metric_query_attributes(request.attributes)?
    } else {
        parse_metric_query_attributes(request.labels)?
    };

    Ok(NormalizedMetricQuery {
        username: request.username,
        metric: MetricQuery {
            name: name.to_string(),
            attributes,
        },
    })
}

fn parse_metric_query_attributes(
    raw_attributes: HashMap<String, Value>,
) -> Result<HashMap<String, String>> {
    raw_attributes
        .into_iter()
        .map(|(key, value)| {
            let normalized_key = key.trim().to_string();
            if normalized_key.is_empty() {
                bail!("Metric attribute names must not be empty");
            }

            let normalized_value = match value {
                Value::String(text) => text,
                Value::Number(number) => number.to_string(),
                Value::Bool(boolean) => boolean.to_string(),
                Value::Null => bail!("Metric attribute '{}' must not be null", normalized_key),
                Value::Array(_) | Value::Object(_) => bail!(
                    "Metric attribute '{}' must be a string, number, or boolean",
                    normalized_key
                ),
            };

            Ok((normalized_key, normalized_value))
        })
        .collect()
}

fn find_metric_value(metrics: &str, query: &MetricQuery) -> Result<String> {
    let samples = parse_metric_samples(metrics)?;
    let named_samples = samples
        .into_iter()
        .filter(|sample| sample.name == query.name)
        .collect::<Vec<_>>();

    if named_samples.is_empty() {
        bail!("Metric '{}' was not found", query.name);
    }

    let matching_samples = named_samples
        .into_iter()
        .filter(|sample| metric_attributes_match(&sample.attributes, &query.attributes))
        .collect::<Vec<_>>();

    match matching_samples.as_slice() {
        [] => bail!(
            "Metric '{}' did not match the requested attributes",
            query.name
        ),
        [sample] => Ok(sample.line.clone()),
        _ => Ok(matching_samples
            .into_iter()
            .map(|sample| sample.line)
            .collect::<Vec<_>>()
            .join("\n")),
    }
}

fn metric_attributes_match(
    sample_attributes: &HashMap<String, String>,
    expected_attributes: &HashMap<String, String>,
) -> bool {
    expected_attributes
        .iter()
        .all(|(key, value)| sample_attributes.get(key) == Some(value))
}

fn parse_metric_samples(metrics: &str) -> Result<Vec<MetricSample>> {
    metrics
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                Some(parse_metric_sample(trimmed))
            }
        })
        .collect()
}

fn parse_metric_sample(line: &str) -> Result<MetricSample> {
    let (identifier, raw_value) = split_metric_sample_line(line)?;
    let (name, attributes) = parse_metric_identifier(identifier)?;
    let value = raw_value
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("Metric sample '{}' is missing a value", line))?;

    Ok(MetricSample {
        name,
        attributes,
        line: line.to_string(),
        value: value.to_string(),
    })
}

pub fn split_metric_sample_line(line: &str) -> Result<(&str, &str)> {
    let mut in_braces = false;
    let mut in_quotes = false;
    let mut escaped = false;

    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' if in_quotes => {
                escaped = true;
            }
            '"' if in_braces => {
                in_quotes = !in_quotes;
            }
            '"' => {
                bail!("Invalid metric sample '{}'", line);
            }
            '{' if !in_quotes => {
                in_braces = true;
            }
            '}' if !in_quotes => {
                in_braces = false;
            }
            ch if ch.is_whitespace() && !in_braces => {
                let identifier = line[..idx].trim();
                let value = line[idx..].trim();
                if identifier.is_empty() || value.is_empty() {
                    bail!("Invalid metric sample '{}'", line);
                }
                return Ok((identifier, value));
            }
            _ => {}
        }
    }

    bail!("Unterminated metric sample '{}'", line)
}

fn parse_metric_identifier(identifier: &str) -> Result<(String, HashMap<String, String>)> {
    if let Some(start) = identifier.find('{') {
        if !identifier.ends_with('}') {
            bail!("Invalid metric label set '{}'", identifier);
        }

        let name = identifier[..start].trim();
        if name.is_empty() {
            bail!("Metric sample is missing a metric name");
        }

        let attributes = parse_metric_attribute_set(&identifier[start + 1..identifier.len() - 1])?;
        Ok((name.to_string(), attributes))
    } else {
        let name = identifier.trim();
        if name.is_empty() {
            bail!("Metric sample is missing a metric name");
        }
        Ok((name.to_string(), HashMap::new()))
    }
}

fn parse_metric_attribute_set(input: &str) -> Result<HashMap<String, String>> {
    let mut attributes = HashMap::new();
    let mut idx = 0;

    while idx < input.len() {
        while idx < input.len() && input.as_bytes()[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= input.len() {
            break;
        }

        let key_start = idx;
        while idx < input.len() && input.as_bytes()[idx] != b'=' {
            idx += 1;
        }
        if idx >= input.len() {
            bail!("Invalid metric label set '{}'", input);
        }

        let key = input[key_start..idx].trim();
        if key.is_empty() {
            bail!("Metric attribute names must not be empty");
        }

        idx += 1;
        if idx >= input.len() || input.as_bytes()[idx] != b'"' {
            bail!("Metric attribute '{}' must use a quoted value", key);
        }
        idx += 1;

        let mut value = String::new();
        let mut closed = false;
        while idx < input.len() {
            match input.as_bytes()[idx] {
                b'\\' => {
                    idx += 1;
                    if idx >= input.len() {
                        bail!("Invalid escape sequence in metric attribute '{}'", key);
                    }

                    match input.as_bytes()[idx] {
                        b'\\' => value.push('\\'),
                        b'"' => value.push('"'),
                        b'n' => value.push('\n'),
                        _ => bail!("Unsupported escape sequence in metric attribute '{}'", key),
                    }
                    idx += 1;
                }
                b'"' => {
                    idx += 1;
                    closed = true;
                    break;
                }
                _ => {
                    let ch = input[idx..]
                        .chars()
                        .next()
                        .ok_or_else(|| anyhow!("Invalid metric label set '{}'", input))?;
                    value.push(ch);
                    idx += ch.len_utf8();
                }
            }
        }

        if !closed {
            bail!("Invalid metric label set '{}'", input);
        }

        attributes.insert(key.to_string(), value);

        while idx < input.len() && input.as_bytes()[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= input.len() {
            break;
        }
        if input.as_bytes()[idx] != b',' {
            bail!("Invalid metric label separator in '{}'", input);
        }
        idx += 1;
    }

    Ok(attributes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::PgmonetaHandler;
    use rmcp::handler::server::router::tool::ToolBase;

    #[test]
    fn test_get_metrics_tool_metadata() {
        assert_eq!(GetMetricsTool::name(), "get_metrics");
        let desc = GetMetricsTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("Prometheus metrics"));
    }

    #[test]
    fn test_metric_tool_metadata() {
        assert_eq!(MetricTool::name(), "metric");
        let desc = MetricTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("single Prometheus metric value"));
    }

    #[test]
    fn test_handler_has_metrics_tools() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"get_metrics"),
            "get_metrics tool should be registered, found: {:?}",
            tool_names
        );
        assert!(
            tool_names.contains(&"metric"),
            "metric tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_normalize_metric_request_accepts_attributes() {
        let query = normalize_metric_request(MetricRequest {
            username: "admin".to_string(),
            name: "pgmoneta_backup_size_bytes".to_string(),
            attributes: HashMap::from([
                ("server".to_string(), Value::String("primary".to_string())),
                ("full".to_string(), Value::Bool(true)),
            ]),
            labels: HashMap::new(),
        })
        .unwrap();

        assert_eq!(query.username, "admin");
        assert_eq!(
            query.metric,
            MetricQuery {
                name: "pgmoneta_backup_size_bytes".to_string(),
                attributes: HashMap::from([
                    ("server".to_string(), "primary".to_string()),
                    ("full".to_string(), "true".to_string()),
                ]),
            }
        );
    }

    #[test]
    fn test_normalize_metric_request_rejects_both_attributes_and_labels() {
        let err = normalize_metric_request(MetricRequest {
            username: "admin".to_string(),
            name: "pgmoneta_up".to_string(),
            attributes: HashMap::from([(
                "server".to_string(),
                Value::String("primary".to_string()),
            )]),
            labels: HashMap::from([("server".to_string(), Value::String("primary".to_string()))]),
        })
        .unwrap_err();

        assert!(err.to_string().contains("either 'attributes' or 'labels'"));
    }

    #[test]
    fn test_find_metric_value_matches_unique_unlabeled_sample() {
        let metrics = "# HELP pgmoneta_up Whether pgmoneta is available.\n\
                       # TYPE pgmoneta_up gauge\n\
                       pgmoneta_up 1\n";

        assert_eq!(
            find_metric_value(
                metrics,
                &MetricQuery {
                    name: "pgmoneta_up".to_string(),
                    attributes: HashMap::new(),
                }
            )
            .unwrap(),
            "pgmoneta_up 1"
        );
    }

    #[test]
    fn test_find_metric_value_matches_labeled_sample() {
        let metrics = "pgmoneta_backup_total{server=\"primary\",type=\"full\"} 4\n\
                       pgmoneta_backup_total{server=\"standby\",type=\"full\"} 2\n";

        assert_eq!(
            find_metric_value(
                metrics,
                &MetricQuery {
                    name: "pgmoneta_backup_total".to_string(),
                    attributes: HashMap::from([("server".to_string(), "primary".to_string())]),
                }
            )
            .unwrap(),
            r#"pgmoneta_backup_total{server="primary",type="full"} 4"#
        );
    }

    #[test]
    fn test_find_metric_value_returns_all_matching_samples() {
        let metrics = "pgmoneta_backup_total{server=\"primary\"} 4\n\
                       pgmoneta_backup_total{server=\"standby\"} 2\n";

        let output = find_metric_value(
            metrics,
            &MetricQuery {
                name: "pgmoneta_backup_total".to_string(),
                attributes: HashMap::new(),
            },
        )
        .unwrap();

        assert_eq!(
            output,
            "pgmoneta_backup_total{server=\"primary\"} 4\npgmoneta_backup_total{server=\"standby\"} 2"
        );
    }

    #[test]
    fn test_parse_metric_attribute_set_unescapes_values() {
        assert_eq!(
            parse_metric_attribute_set(r#"path="/metrics",note="line\nbreak",quote="a\"b""#)
                .unwrap(),
            HashMap::from([
                ("path".to_string(), "/metrics".to_string()),
                ("note".to_string(), "line\nbreak".to_string()),
                ("quote".to_string(), "a\"b".to_string()),
            ])
        );
    }

    #[test]
    fn test_parse_metric_sample_label_with_braces() {
        let sample = parse_metric_sample(r#"pgmoneta_query{q="select {x} from t"} 7"#).unwrap();
        assert_eq!(sample.value, "7");
        assert_eq!(
            sample.attributes.get("q").map(String::as_str),
            Some("select {x} from t")
        );
    }

    #[test]
    fn test_parse_metric_sample_escaped_quote_and_brace() {
        let sample = parse_metric_sample(r#"m{q="a\"} b"} 3"#).unwrap();
        assert_eq!(sample.value, "3");
        assert_eq!(
            sample.attributes.get("q").map(String::as_str),
            Some(r#"a"} b"#)
        );
    }

    #[test]
    fn test_parse_metric_sample_stray_quote_outside_braces() {
        assert!(parse_metric_sample(r#"pgmoneta" 1"#).is_err());
    }

    #[test]
    fn test_parse_metric_sample_unterminated_quote() {
        let result = parse_metric_sample(r#"pgmoneta_query{q="unterminated} 7"#);
        assert!(
            result.is_err(),
            "unterminated quote must be an error and must not yield value 7"
        );
    }

    #[test]
    fn test_parse_metric_sample_regression_guards() {
        let sample1 = parse_metric_sample("up 1").unwrap();
        assert_eq!(sample1.value, "1");

        let sample2 = parse_metric_sample("up 1 1700000000").unwrap();
        assert_eq!(sample2.value, "1");
    }

    #[test]
    fn test_parse_metric_attribute_set_unclosed_quote() {
        assert!(parse_metric_attribute_set(r#"q="abc"#).is_err());
    }

    #[test]
    fn test_normalize_metric_request_accepts_labels() {
        let query = normalize_metric_request(MetricRequest {
            username: "admin".to_string(),
            name: "pgmoneta_up".to_string(),
            attributes: HashMap::new(),
            labels: HashMap::from([("server".to_string(), Value::String("primary".to_string()))]),
        })
        .unwrap();

        assert_eq!(
            query.metric.attributes.get("server").map(String::as_str),
            Some("primary")
        );
    }

    #[test]
    fn test_normalize_metric_request_rejects_empty_name() {
        let err = normalize_metric_request(MetricRequest {
            username: "admin".to_string(),
            name: "   ".to_string(),
            attributes: HashMap::new(),
            labels: HashMap::new(),
        })
        .unwrap_err();

        assert!(err.to_string().contains("requires a non-empty 'name'"));
    }

    #[test]
    fn test_normalize_metric_request_rejects_null_attribute() {
        let err = normalize_metric_request(MetricRequest {
            username: "admin".to_string(),
            name: "pgmoneta_up".to_string(),
            attributes: HashMap::from([("server".to_string(), Value::Null)]),
            labels: HashMap::new(),
        })
        .unwrap_err();

        assert!(err.to_string().contains("must not be null"));
    }

    #[test]
    fn test_normalize_metric_request_rejects_nested_attribute() {
        let err = normalize_metric_request(MetricRequest {
            username: "admin".to_string(),
            name: "pgmoneta_up".to_string(),
            attributes: HashMap::from([(
                "server".to_string(),
                Value::Array(vec![Value::String("primary".to_string())]),
            )]),
            labels: HashMap::new(),
        })
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("must be a string, number, or boolean")
        );
    }

    #[test]
    fn test_find_metric_value_not_found() {
        let metrics = "pgmoneta_up 1\n";
        let err = find_metric_value(
            metrics,
            &MetricQuery {
                name: "pgmoneta_version".to_string(),
                attributes: HashMap::new(),
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("was not found"));
    }

    #[test]
    fn test_find_metric_value_attributes_mismatch() {
        let metrics = r#"pgmoneta_backup_total{server="primary"} 5"#;
        let err = find_metric_value(
            metrics,
            &MetricQuery {
                name: "pgmoneta_backup_total".to_string(),
                attributes: HashMap::from([("server".to_string(), "replica".to_string())]),
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("did not match"));
    }

    #[test]
    fn test_parse_metric_sample_with_timestamp_and_labels() {
        let sample =
            parse_metric_sample(r#"pgmoneta_backup_total{server="primary"} 5 1715000000000"#)
                .unwrap();
        assert_eq!(sample.name, "pgmoneta_backup_total");
        assert_eq!(sample.value, "5");
        assert_eq!(
            sample.attributes.get("server").map(String::as_str),
            Some("primary")
        );
    }

    #[test]
    fn test_parse_metric_attribute_set_rejects_unsupported_escape() {
        assert!(parse_metric_attribute_set(r#"q="a\tb""#).is_err());
    }
}
