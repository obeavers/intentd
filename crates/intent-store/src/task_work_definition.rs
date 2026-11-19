//! Validate prospective structured requirements against their exact note source.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use intent_core::{Error, Result, TaskMetadata};
use sha2::{Digest, Sha256};

fn invalid(reason: &str) -> Error {
    Error::InvalidParams(format!("Task work definition: {reason}"))
}

pub(crate) fn text_digest(text: &str) -> String {
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(text.as_bytes()) {
        write!(&mut result, "{byte:02x}").expect("writing into a string");
    }
    result
}

pub(crate) fn validate(task: &TaskMetadata) -> Result<()> {
    let Some(definition) = &task.work_definition else {
        return Ok(());
    };
    let encoded = serde_json::to_vec(definition)
        .map_err(|error| Error::Internal(format!("Encode task work definition: {error}")))?;
    if encoded.len() > 64 * 1024 || definition.criteria.len() > 128 || definition.files.len() > 512
    {
        return Err(invalid("declared requirements exceed their bounded budget"));
    }
    let mut indices = BTreeSet::new();
    for criterion in &definition.criteria {
        let text = usize::try_from(criterion.index)
            .ok()
            .and_then(|index| task.acceptance_criteria.get(index))
            .ok_or_else(|| invalid("criterion index does not name this task's source"))?;
        if !indices.insert(criterion.index) || text_digest(text) != criterion.text_digest.as_str() {
            return Err(invalid("criterion text changed or its index was repeated"));
        }
        let mut kinds = BTreeSet::new();
        if criterion.required_kinds.is_empty() || criterion.required_kinds.len() > 16 {
            return Err(invalid(
                "a declared criterion needs one to sixteen required kinds",
            ));
        }
        for kind in &criterion.required_kinds {
            if kind.is_empty()
                || kind.len() > 64
                || !kind
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || !kinds.insert(kind)
            {
                return Err(invalid(
                    "evidence kinds must be unique bounded lowercase identifiers",
                ));
            }
        }
    }
    let mut files = BTreeSet::new();
    for file in &definition.files {
        if file.root_id.is_empty()
            || file.root_id.len() > 256
            || !file
                .root_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || file.path.is_empty()
            || file.path.len() > 4096
            || file.path.contains(['\\', ':'])
            || file.path.chars().any(char::is_control)
            || (file.path != "."
                && file
                    .path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == ".."))
            || !files.insert((&file.root_id, &file.path))
        {
            return Err(invalid(
                "file references need unique exact roots and relative slash paths",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent_core::vcs::ContentDigest;
    use intent_core::work_evidence::planning::{
        TaskCriterionRequirement, TaskFileReference, TaskFileRole, TaskWorkDefinition,
        TaskWorkPurpose,
    };

    fn task() -> TaskMetadata {
        TaskMetadata {
            acceptance_criteria: vec!["Preserve exact bytes".into()],
            work_definition: Some(TaskWorkDefinition {
                purpose: TaskWorkPurpose::Source,
                criteria: vec![TaskCriterionRequirement {
                    index: 0,
                    text_digest: ContentDigest(text_digest("Preserve exact bytes")),
                    required_kinds: vec!["round-trip".into(), "typecheck".into()],
                }],
                files: vec![TaskFileReference {
                    root_id: "primary".into(),
                    path: "src/data.rs".into(),
                    role: TaskFileRole::InScope,
                }],
            }),
            ..TaskMetadata::default()
        }
    }

    #[test]
    fn exact_criterion_source_is_required_and_legacy_tasks_remain_undeclared() {
        validate(&TaskMetadata::default()).unwrap();
        let mut task = task();
        validate(&task).unwrap();
        task.acceptance_criteria[0].push(' ');
        assert!(validate(&task).is_err());
    }

    #[test]
    fn duplicate_or_malformed_kinds_paths_and_indices_never_become_requirements() {
        for path in [
            "/etc/passwd",
            "../escape",
            "src//double",
            "C:/host",
            "src\\windows",
            "src/./alias",
        ] {
            let mut task = task();
            task.work_definition.as_mut().unwrap().files[0].path = path.into();
            assert!(validate(&task).is_err(), "{path}");
        }
        let mut duplicate = task();
        let source = duplicate.work_definition.as_mut().unwrap();
        source.criteria.push(source.criteria[0].clone());
        assert!(validate(&duplicate).is_err());
        let mut missing = task();
        missing.work_definition.as_mut().unwrap().criteria[0].index = 1;
        assert!(validate(&missing).is_err());
        for kinds in [
            vec![],
            vec!["typecheck".into(), "typecheck".into()],
            vec!["Passed!".into()],
        ] {
            let mut task = task();
            task.work_definition.as_mut().unwrap().criteria[0].required_kinds = kinds;
            assert!(validate(&task).is_err());
        }
    }
}
