use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::error::AppError;

#[derive(Debug, Deserialize)]
pub struct PackageJson {
    pub version: String,
    pub platform: String,
    #[serde(rename = "eleArch")]
    pub ele_arch: String,
}

#[derive(Debug, Deserialize)]
pub struct VersionJson {
    pub wrapper: WrapperInfo,
    pub appinfo: Value,
}

#[derive(Debug, Deserialize)]
pub struct WrapperInfo {
    pub sign_offset: String,
}

impl WrapperInfo {
    pub fn offset(&self) -> Result<usize, AppError> {
        let s = self.sign_offset.strip_prefix("0x").unwrap_or(&self.sign_offset);
        usize::from_str_radix(s, 16).map_err(|e| AppError::Config(format!("invalid sign_offset: {}", e)))
    }
}

#[derive(Debug, Deserialize)]
struct IndexEntry {
    file: String,
}

pub struct VersionData {
    pub version_key: String,
    pub sign_offset: usize,
    pub appinfo: Value,
}

pub fn load(runtime_app: &Path, versions_dir: &Path) -> Result<VersionData, AppError> {
    // Read package.json
    let pkg_path = runtime_app.join("package.json");
    let pkg_content = std::fs::read_to_string(&pkg_path)?;
    let pkg: PackageJson = serde_json::from_str(&pkg_content)?;

    // Construct version key
    let version_key = format!("{}-{}/{}", pkg.platform, pkg.ele_arch, pkg.version);
    tracing::info!("detected QQ version: {}", version_key);

    // Load index.json
    let index_path = versions_dir.join("index.json");
    let index_content = std::fs::read_to_string(&index_path)?;
    let index: HashMap<String, IndexEntry> = serde_json::from_str(&index_content)?;

    let entry = index.get(&version_key)
        .ok_or_else(|| AppError::VersionNotFound(version_key.clone()))?;

    // Load version JSON
    let ver_path = versions_dir.join(&entry.file);
    let ver_content = std::fs::read_to_string(&ver_path)?;
    let ver: VersionJson = serde_json::from_str(&ver_content)?;

    let sign_offset = ver.wrapper.offset()?;

    Ok(VersionData {
        version_key,
        sign_offset,
        appinfo: ver.appinfo,
    })
}
