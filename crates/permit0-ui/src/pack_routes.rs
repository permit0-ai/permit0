#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use permit0_dsl::schema::normalizer::NormalizerDef;
use permit0_dsl::schema::pack::PackManifest;
use permit0_dsl::schema::risk_rule::RiskRuleDef;
use permit0_dsl::validate::{validate_normalizer, validate_risk_rule};

use crate::state::AppState;

// ── Response Envelope ──

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub ok: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

fn ok_response<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        ok: true,
        data: Some(data),
        error: None,
    })
}

fn err_response<T: Serialize>(status: StatusCode, msg: &str) -> (StatusCode, Json<ApiResponse<T>>) {
    (
        status,
        Json(ApiResponse {
            ok: false,
            data: None,
            error: Some(msg.into()),
        }),
    )
}

// ── Response Types ──

#[derive(Debug, Serialize)]
pub struct PackSummary {
    pub name: String,
    pub version: String,
    /// Pack owner. Derived from `permit0_pack` ("<owner>/<name>") since
    /// schema v2 drops the explicit `vendor` field. Falls back to the
    /// legacy `vendor` value if `permit0_pack` is malformed.
    pub vendor: String,
    pub description: Option<String>,
    pub normalizer_count: usize,
    pub risk_rule_count: usize,
}

#[derive(Debug, Serialize)]
pub struct PackDetail {
    pub name: String,
    pub version: String,
    pub vendor: String,
    pub description: Option<String>,
    pub normalizers: Vec<String>,
    pub risk_rules: Vec<String>,
}

/// Resolve the pack owner. Pulls from `permit0_pack` ("<owner>/<name>") in
/// schema v2; falls back to the legacy `vendor` field for transitional
/// safety.
fn resolve_owner(manifest: &PackManifest) -> String {
    manifest
        .permit0_pack
        .split_once('/')
        .map(|(owner, _)| owner.to_string())
        .or_else(|| manifest.vendor.clone())
        .unwrap_or_default()
}

#[derive(Debug, Serialize)]
pub struct FileDetail<M: Serialize> {
    pub filename: String,
    pub yaml: String,
    pub meta: Option<M>,
}

#[derive(Debug, Serialize)]
pub struct NormalizerMeta {
    pub id: String,
    pub action_type: String,
    pub priority: i32,
    pub channel: String,
}

#[derive(Debug, Serialize)]
pub struct RiskRuleMeta {
    pub action_type: String,
    pub flags: HashMap<String, String>,
    pub amplifiers: HashMap<String, i32>,
}

#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub errors: Vec<String>,
}

// ── Request Types ──

#[derive(Debug, Deserialize)]
pub struct UpdateRequest {
    pub yaml: String,
}

#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub kind: String,
    pub yaml: String,
}

// ── Path Sanitization ──

/// Validate a pack name: must match `[a-zA-Z0-9_-]+`.
fn sanitize_pack_name(s: &str) -> Result<&str, String> {
    if s.is_empty() {
        return Err("pack name must not be empty".into());
    }
    if s.contains("..") || s.contains('/') || s.contains('\\') || s.contains('\0') {
        return Err(format!("invalid pack name: {s}"));
    }
    let valid = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !valid {
        return Err(format!("invalid pack name: {s}"));
    }
    Ok(s)
}

/// Validate a YAML filename: must match `[a-zA-Z0-9_-]+\.ya?ml`.
fn sanitize_filename(s: &str) -> Result<&str, String> {
    if s.is_empty() {
        return Err("filename must not be empty".into());
    }
    if s.contains("..") || s.contains('/') || s.contains('\\') || s.contains('\0') {
        return Err(format!("invalid filename: {s}"));
    }
    // Split at last dot to check extension
    let (stem, ext) = match s.rfind('.') {
        Some(pos) if pos > 0 => (&s[..pos], &s[pos + 1..]),
        _ => return Err(format!("invalid filename (no extension): {s}")),
    };
    if ext != "yaml" && ext != "yml" {
        return Err(format!("invalid filename extension: {s}"));
    }
    let stem_valid = stem
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !stem_valid {
        return Err(format!("invalid filename stem: {s}"));
    }
    Ok(s)
}

#[cfg(test)]
fn sanitize_path_param(s: &str) -> Result<&str, String> {
    if s.is_empty() {
        return Err("path parameter must not be empty".into());
    }
    if s.contains("..") || s.contains('/') || s.contains('\\') || s.contains('\0') {
        return Err(format!("invalid path parameter: {s}"));
    }
    Ok(s)
}

// ── Helpers ──

fn resolve_packs_dir(state: &AppState) -> Result<PathBuf, (StatusCode, Json<ApiResponse<()>>)> {
    state.packs_dir.clone().ok_or_else(|| {
        err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "packs_dir is not configured",
        )
    })
}

fn list_yaml_files(dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yaml" || ext == "yml" {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            files.push(name.to_string());
                        }
                    }
                }
            }
        }
    }
    files.sort();
    files
}

// ── Route Handlers ──

/// GET /api/v1/packs
pub async fn list_packs(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<PackSummary>>>, (StatusCode, Json<ApiResponse<Vec<PackSummary>>>)>
{
    let packs_dir = resolve_packs_dir(&state).map_err(|(_status, _body)| {
        err_response::<Vec<PackSummary>>(
            StatusCode::INTERNAL_SERVER_ERROR,
            "packs_dir is not configured",
        )
    })?;

    let entries = std::fs::read_dir(&packs_dir).map_err(|e| {
        err_response::<Vec<PackSummary>>(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to read packs directory: {e}"),
        )
    })?;

    let mut summaries = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("pack.yaml");
        if !manifest_path.exists() {
            continue;
        }
        let content = match std::fs::read_to_string(&manifest_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let manifest: PackManifest = match serde_yaml::from_str(&content) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let vendor = resolve_owner(&manifest);
        summaries.push(PackSummary {
            normalizer_count: manifest.normalizers.len(),
            risk_rule_count: manifest.risk_rules.len(),
            name: manifest.name,
            version: manifest.version,
            vendor,
            description: manifest.description,
        });
    }
    summaries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ok_response(summaries))
}

/// GET /api/v1/packs/{pack_name}
pub async fn get_pack(
    State(state): State<AppState>,
    AxumPath(pack_name): AxumPath<String>,
) -> Result<Json<ApiResponse<PackDetail>>, (StatusCode, Json<ApiResponse<PackDetail>>)> {
    let pack_name = sanitize_pack_name(&pack_name)
        .map_err(|e| err_response::<PackDetail>(StatusCode::BAD_REQUEST, &e))?;

    let packs_dir = resolve_packs_dir(&state).map_err(|(_status, _body)| {
        err_response::<PackDetail>(
            StatusCode::INTERNAL_SERVER_ERROR,
            "packs_dir is not configured",
        )
    })?;

    let pack_path = packs_dir.join(pack_name);
    let manifest_path = pack_path.join("pack.yaml");

    let content = std::fs::read_to_string(&manifest_path).map_err(|e| {
        err_response::<PackDetail>(StatusCode::NOT_FOUND, &format!("pack not found: {e}"))
    })?;

    let manifest: PackManifest = serde_yaml::from_str(&content).map_err(|e| {
        err_response::<PackDetail>(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to parse pack.yaml: {e}"),
        )
    })?;

    let normalizers = list_yaml_files(&pack_path.join("normalizers"));
    let risk_rules = list_yaml_files(&pack_path.join("risk_rules"));

    let vendor = resolve_owner(&manifest);
    Ok(ok_response(PackDetail {
        name: manifest.name,
        version: manifest.version,
        vendor,
        description: manifest.description,
        normalizers,
        risk_rules,
    }))
}

/// GET /api/v1/packs/{pack_name}/normalizers/{filename}
pub async fn get_normalizer(
    State(state): State<AppState>,
    AxumPath((pack_name, filename)): AxumPath<(String, String)>,
) -> Result<
    Json<ApiResponse<FileDetail<NormalizerMeta>>>,
    (StatusCode, Json<ApiResponse<FileDetail<NormalizerMeta>>>),
> {
    let pack_name = sanitize_pack_name(&pack_name)
        .map_err(|e| err_response::<FileDetail<NormalizerMeta>>(StatusCode::BAD_REQUEST, &e))?;
    let filename = sanitize_filename(&filename)
        .map_err(|e| err_response::<FileDetail<NormalizerMeta>>(StatusCode::BAD_REQUEST, &e))?;

    let packs_dir = resolve_packs_dir(&state).map_err(|(_status, _body)| {
        err_response::<FileDetail<NormalizerMeta>>(
            StatusCode::INTERNAL_SERVER_ERROR,
            "packs_dir is not configured",
        )
    })?;

    let file_path = packs_dir.join(pack_name).join("normalizers").join(filename);

    let yaml = std::fs::read_to_string(&file_path).map_err(|e| {
        err_response::<FileDetail<NormalizerMeta>>(
            StatusCode::NOT_FOUND,
            &format!("normalizer file not found: {e}"),
        )
    })?;

    let meta = serde_yaml::from_str::<NormalizerDef>(&yaml)
        .ok()
        .map(|def| NormalizerMeta {
            id: def.id,
            action_type: def.normalize.action_type,
            priority: def.priority,
            channel: def.normalize.channel,
        });

    Ok(ok_response(FileDetail {
        filename: filename.to_string(),
        yaml,
        meta,
    }))
}

/// GET /api/v1/packs/{pack_name}/risk_rules/{filename}
pub async fn get_risk_rule(
    State(state): State<AppState>,
    AxumPath((pack_name, filename)): AxumPath<(String, String)>,
) -> Result<
    Json<ApiResponse<FileDetail<RiskRuleMeta>>>,
    (StatusCode, Json<ApiResponse<FileDetail<RiskRuleMeta>>>),
> {
    let pack_name = sanitize_pack_name(&pack_name)
        .map_err(|e| err_response::<FileDetail<RiskRuleMeta>>(StatusCode::BAD_REQUEST, &e))?;
    let filename = sanitize_filename(&filename)
        .map_err(|e| err_response::<FileDetail<RiskRuleMeta>>(StatusCode::BAD_REQUEST, &e))?;

    let packs_dir = resolve_packs_dir(&state).map_err(|(_status, _body)| {
        err_response::<FileDetail<RiskRuleMeta>>(
            StatusCode::INTERNAL_SERVER_ERROR,
            "packs_dir is not configured",
        )
    })?;

    let file_path = packs_dir.join(pack_name).join("risk_rules").join(filename);

    let yaml = std::fs::read_to_string(&file_path).map_err(|e| {
        err_response::<FileDetail<RiskRuleMeta>>(
            StatusCode::NOT_FOUND,
            &format!("risk rule file not found: {e}"),
        )
    })?;

    let meta = serde_yaml::from_str::<RiskRuleDef>(&yaml)
        .ok()
        .map(|def| RiskRuleMeta {
            action_type: def.action_type,
            flags: def.base.flags,
            amplifiers: def.base.amplifiers,
        });

    Ok(ok_response(FileDetail {
        filename: filename.to_string(),
        yaml,
        meta,
    }))
}

/// PUT /api/v1/packs/{pack_name}/normalizers/{filename}
pub async fn update_normalizer(
    State(state): State<AppState>,
    AxumPath((pack_name, filename)): AxumPath<(String, String)>,
    Json(req): Json<UpdateRequest>,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<String>>)> {
    let pack_name = sanitize_pack_name(&pack_name)
        .map_err(|e| err_response::<String>(StatusCode::BAD_REQUEST, &e))?;
    let filename = sanitize_filename(&filename)
        .map_err(|e| err_response::<String>(StatusCode::BAD_REQUEST, &e))?;

    let packs_dir = resolve_packs_dir(&state).map_err(|(_status, _body)| {
        err_response::<String>(
            StatusCode::INTERNAL_SERVER_ERROR,
            "packs_dir is not configured",
        )
    })?;

    let def: NormalizerDef = serde_yaml::from_str(&req.yaml).map_err(|e| {
        err_response::<String>(StatusCode::BAD_REQUEST, &format!("invalid YAML: {e}"))
    })?;

    let validation_errors = validate_normalizer(&def);
    if !validation_errors.is_empty() {
        let msgs: Vec<String> = validation_errors.iter().map(|e| e.to_string()).collect();
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            &format!("validation failed: {}", msgs.join("; ")),
        ));
    }

    let file_path = packs_dir.join(pack_name).join("normalizers").join(filename);

    std::fs::write(&file_path, &req.yaml).map_err(|e| {
        err_response::<String>(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to write file: {e}"),
        )
    })?;

    Ok(ok_response("normalizer updated".to_string()))
}

/// PUT /api/v1/packs/{pack_name}/risk_rules/{filename}
pub async fn update_risk_rule(
    State(state): State<AppState>,
    AxumPath((pack_name, filename)): AxumPath<(String, String)>,
    Json(req): Json<UpdateRequest>,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<String>>)> {
    let pack_name = sanitize_pack_name(&pack_name)
        .map_err(|e| err_response::<String>(StatusCode::BAD_REQUEST, &e))?;
    let filename = sanitize_filename(&filename)
        .map_err(|e| err_response::<String>(StatusCode::BAD_REQUEST, &e))?;

    let packs_dir = resolve_packs_dir(&state).map_err(|(_status, _body)| {
        err_response::<String>(
            StatusCode::INTERNAL_SERVER_ERROR,
            "packs_dir is not configured",
        )
    })?;

    let def: RiskRuleDef = serde_yaml::from_str(&req.yaml).map_err(|e| {
        err_response::<String>(StatusCode::BAD_REQUEST, &format!("invalid YAML: {e}"))
    })?;

    let validation_errors = validate_risk_rule(&def);
    if !validation_errors.is_empty() {
        let msgs: Vec<String> = validation_errors.iter().map(|e| e.to_string()).collect();
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            &format!("validation failed: {}", msgs.join("; ")),
        ));
    }

    let file_path = packs_dir.join(pack_name).join("risk_rules").join(filename);

    std::fs::write(&file_path, &req.yaml).map_err(|e| {
        err_response::<String>(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to write file: {e}"),
        )
    })?;

    Ok(ok_response("risk rule updated".to_string()))
}

/// POST /api/v1/packs/validate
pub async fn validate_yaml(
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ApiResponse<ValidateResponse>>, (StatusCode, Json<ApiResponse<ValidateResponse>>)>
{
    match req.kind.as_str() {
        "normalizer" => {
            let def: NormalizerDef = match serde_yaml::from_str(&req.yaml) {
                Ok(d) => d,
                Err(e) => {
                    return Ok(ok_response(ValidateResponse {
                        valid: false,
                        errors: vec![format!("YAML parse error: {e}")],
                    }));
                }
            };
            let validation_errors = validate_normalizer(&def);
            let errors: Vec<String> = validation_errors.iter().map(|e| e.to_string()).collect();
            Ok(ok_response(ValidateResponse {
                valid: errors.is_empty(),
                errors,
            }))
        }
        "risk_rule" => {
            let def: RiskRuleDef = match serde_yaml::from_str(&req.yaml) {
                Ok(d) => d,
                Err(e) => {
                    return Ok(ok_response(ValidateResponse {
                        valid: false,
                        errors: vec![format!("YAML parse error: {e}")],
                    }));
                }
            };
            let validation_errors = validate_risk_rule(&def);
            let errors: Vec<String> = validation_errors.iter().map(|e| e.to_string()).collect();
            Ok(ok_response(ValidateResponse {
                valid: errors.is_empty(),
                errors,
            }))
        }
        other => Err(err_response(
            StatusCode::BAD_REQUEST,
            &format!("unknown kind: {other} (expected 'normalizer' or 'risk_rule')"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sanitize_path_param tests ──

    #[test]
    fn sanitize_path_param_rejects_dot_dot() {
        assert!(sanitize_path_param("../etc").is_err());
        assert!(sanitize_path_param("foo/../bar").is_err());
    }

    #[test]
    fn sanitize_path_param_rejects_slash() {
        assert!(sanitize_path_param("foo/bar").is_err());
    }

    #[test]
    fn sanitize_path_param_rejects_backslash() {
        assert!(sanitize_path_param("foo\\bar").is_err());
    }

    #[test]
    fn sanitize_path_param_rejects_empty() {
        assert!(sanitize_path_param("").is_err());
    }

    #[test]
    fn sanitize_path_param_accepts_valid_names() {
        assert_eq!(sanitize_path_param("shell"), Ok("shell"));
        assert_eq!(sanitize_path_param("file_write"), Ok("file_write"));
        assert_eq!(sanitize_path_param("my-pack"), Ok("my-pack"));
        assert_eq!(sanitize_path_param("pack123"), Ok("pack123"));
    }

    // ── sanitize_pack_name tests ──

    #[test]
    fn sanitize_pack_name_accepts_valid() {
        assert_eq!(sanitize_pack_name("shell"), Ok("shell"));
        assert_eq!(sanitize_pack_name("file_write"), Ok("file_write"));
        assert_eq!(sanitize_pack_name("my-pack"), Ok("my-pack"));
    }

    #[test]
    fn sanitize_pack_name_rejects_traversal() {
        assert!(sanitize_pack_name("..").is_err());
        assert!(sanitize_pack_name("../evil").is_err());
    }

    #[test]
    fn sanitize_pack_name_rejects_special_chars() {
        assert!(sanitize_pack_name("foo.bar").is_err());
        assert!(sanitize_pack_name("foo bar").is_err());
    }

    // ── sanitize_filename tests ──

    #[test]
    fn sanitize_filename_accepts_yaml() {
        assert_eq!(sanitize_filename("shell.yaml"), Ok("shell.yaml"));
        assert_eq!(sanitize_filename("file-write.yaml"), Ok("file-write.yaml"));
        assert_eq!(sanitize_filename("read.yml"), Ok("read.yml"));
        assert_eq!(
            sanitize_filename("my_normalizer.yaml"),
            Ok("my_normalizer.yaml")
        );
    }

    #[test]
    fn sanitize_filename_rejects_traversal() {
        assert!(sanitize_filename("../evil.yaml").is_err());
        assert!(sanitize_filename("foo/../bar.yaml").is_err());
    }

    #[test]
    fn sanitize_filename_rejects_dotenv() {
        assert!(sanitize_filename(".env").is_err());
    }

    #[test]
    fn sanitize_filename_rejects_non_yaml() {
        assert!(sanitize_filename("script.sh").is_err());
        assert!(sanitize_filename("data.json").is_err());
    }

    #[test]
    fn sanitize_filename_rejects_no_extension() {
        assert!(sanitize_filename("noext").is_err());
    }

    #[test]
    fn sanitize_filename_rejects_empty_stem() {
        assert!(sanitize_filename(".yaml").is_err());
    }

    // ── list_yaml_files tests ──

    #[test]
    fn list_yaml_files_nonexistent_dir() {
        let files = list_yaml_files(Path::new("/nonexistent/path/xyz"));
        assert!(files.is_empty());
    }

    #[test]
    fn list_yaml_files_returns_sorted() {
        let tmp = std::env::temp_dir().join("permit0_test_list_yaml");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("zebra.yaml"), "").unwrap();
        std::fs::write(tmp.join("alpha.yaml"), "").unwrap();
        std::fs::write(tmp.join("middle.yml"), "").unwrap();
        std::fs::write(tmp.join("ignore.txt"), "").unwrap();

        let files = list_yaml_files(&tmp);
        assert_eq!(files, vec!["alpha.yaml", "middle.yml", "zebra.yaml"]);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
