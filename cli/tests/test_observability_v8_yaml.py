# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib

import pytest
import yaml
from defenseclaw.observability.v8_yaml import (
    V8YAMLMutation,
    V8YAMLMutationError,
    prepare_v8_yaml_write,
)


def test_noop_is_byte_identical_with_comments_ascii_unicode_and_quotes() -> None:
    source = (
        "# ┌── OBSERVABILITY: collect → route ──┐\n"
        "config_version: 8\n"
        "name: café 🛡️ # before\n"
        "observability:\n"
        "  # keep inside\n"
        "  local: {path: '/tmp/audit.db', retention_days: 90} # inline\n"
        'after: "quoted" # after\n'
    ).encode()

    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.set(("observability", "local", "retention_days"), 90)],
    )

    assert prepared.candidate == source
    assert prepared.changed is False
    assert prepared.expected_sha256 == hashlib.sha256(source).hexdigest()
    assert prepared.candidate_sha256 == prepared.expected_sha256


def test_block_scalar_patch_preserves_all_unrelated_text_and_quote_style() -> None:
    source = """# header
# ┌──── knobs ────┐
config_version: 8
before: keep # before observability
observability:
  # local explanation
  local:
    path: '/old path' # path comment
    retention_days: 90 # retained
  # route explanation
  destinations:
    - name: otel # destination name
      kind: otlp
      endpoint: "https://old.example.test" # endpoint comment
      routes:
        - name: findings # first route comment
          signals: [logs]
          selector: {buckets: [security.finding]}
after: keep # after observability
"""
    prepared = prepare_v8_yaml_write(
        source,
        [
            V8YAMLMutation.set(("observability", "local", "path"), "/new path"),
            V8YAMLMutation.set(("observability", "destinations", 0, "endpoint"), "https://new.example.test"),
        ],
    )
    candidate = prepared.candidate.decode()

    assert "path: '/new path' # path comment" in candidate
    assert 'endpoint: "https://new.example.test" # endpoint comment' in candidate
    for preserved in (
        "# header",
        "# ┌──── knobs ────┐",
        "before: keep # before observability",
        "# local explanation",
        "retention_days: 90 # retained",
        "# route explanation",
        "name: otel # destination name",
        "name: findings # first route comment",
        "selector: {buckets: [security.finding]}",
        "after: keep # after observability",
    ):
        assert preserved in candidate
    assert list(yaml.safe_load(candidate)) == ["config_version", "before", "observability", "after"]


def test_control_characters_are_safely_escaped_in_existing_quotes() -> None:
    source = 'config_version: 8\nobservability: {local: {path: "old"}}\n'
    value = "line one\nline two\t\u0001"
    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.set(("observability", "local", "path"), value)],
    )

    assert yaml.safe_load(prepared.candidate)["observability"]["local"]["path"] == value
    assert b"\\n" in prepared.candidate
    assert b"\\u0001" in prepared.candidate


def test_flow_style_patch_insert_and_delete_stays_flow_style() -> None:
    source = "config_version: 8\nobservability: {local: {path: '/old', retention_days: 90}, metric_policy: {temporality: delta}}\n"
    prepared = prepare_v8_yaml_write(
        source,
        [
            V8YAMLMutation.set(("observability", "local", "path"), "/new"),
            V8YAMLMutation.set(("observability", "local", "judge_bodies_path"), "/judge.db"),
            V8YAMLMutation.delete(("observability", "local", "retention_days")),
        ],
    )
    candidate = prepared.candidate.decode()

    assert "local: {path: '/new', judge_bodies_path: /judge.db}" in candidate
    assert "metric_policy: {temporality: delta}" in candidate
    assert yaml.safe_load(candidate)["observability"]["local"] == {
        "path": "/new",
        "judge_bodies_path": "/judge.db",
    }


def test_insertion_builds_only_missing_observability_ancestors() -> None:
    source = "# existing header\nconfig_version: 8\nunrelated: {order: preserved}\n"
    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.set(("observability", "buckets", "model.io", "collect", "logs"), False)],
    )
    candidate = prepared.candidate.decode()

    assert candidate.startswith(source)
    assert "# existing header" in candidate
    assert yaml.safe_load(candidate)["observability"] == {"buckets": {"model.io": {"collect": {"logs": False}}}}


def test_block_deletion_does_not_touch_neighbor_comments_or_order() -> None:
    source = """config_version: 8
observability:
  local:
    path: /audit.db # remove with field
    # retention belongs to the next key
    retention_days: 90
  metric_policy:
    temporality: delta
"""
    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.delete(("observability", "local", "path"))],
    )
    candidate = prepared.candidate.decode()

    assert "path:" not in candidate
    assert "# retention belongs to the next key" in candidate
    assert candidate.index("local:") < candidate.index("metric_policy:")
    assert yaml.safe_load(candidate)["observability"]["local"] == {"retention_days": 90}


def test_block_insertion_uses_parent_indent_and_preserves_following_sibling() -> None:
    source = """config_version: 8
observability:
  local:
    path: /audit.db
  metric_policy: # following sibling
    temporality: delta
"""
    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.set(("observability", "local", "judge_bodies_path"), "/judge.db")],
    )
    candidate = prepared.candidate.decode()

    assert "    judge_bodies_path: /judge.db\n  metric_policy: # following sibling" in candidate
    assert yaml.safe_load(candidate)["observability"]["local"]["judge_bodies_path"] == "/judge.db"


def test_block_sequence_replacement_keeps_existing_indent() -> None:
    source = """config_version: 8
observability:
  redaction_profiles:
    soc:
      extends: sensitive
      detectors:
        - pii
        - credentials
      # comment belongs to following field
      field_classes: # following field
        content: detect
"""
    prepared = prepare_v8_yaml_write(
        source,
        [
            V8YAMLMutation.set(
                ("observability", "redaction_profiles", "soc", "detectors"),
                ["pii", "credentials", "secrets"],
            )
        ],
    )
    candidate = prepared.candidate.decode()

    assert (
        "      detectors:\n        - pii\n        - credentials\n        - secrets\n"
        "      # comment belongs to following field\n      field_classes:" in candidate
    )
    assert yaml.safe_load(candidate)["observability"]["redaction_profiles"]["soc"]["detectors"] == [
        "pii",
        "credentials",
        "secrets",
    ]


def test_deleting_last_block_entries_leaves_typed_empty_containers() -> None:
    source = """config_version: 8
observability:
  buckets:
    model.io:
      collect: {logs: false}
  destinations:
    - name: only
      kind: console
"""
    prepared = prepare_v8_yaml_write(
        source,
        [
            V8YAMLMutation.delete(("observability", "buckets", "model.io")),
            V8YAMLMutation.delete(("observability", "destinations", 0)),
        ],
    )

    observability = yaml.safe_load(prepared.candidate)["observability"]
    assert observability["buckets"] == {}
    assert observability["destinations"] == []
    assert "buckets:\n    {}" in prepared.candidate.decode()
    assert "destinations:\n    []" in prepared.candidate.decode()


def test_destination_append_and_delete_preserve_other_item_comments() -> None:
    source = """config_version: 8
observability:
  destinations:
    - name: first # keep first comment
      kind: console
    - name: removed # removed comment
      kind: console
  # comment belongs to local
  local:
    retention_days: 90 # keep after list
"""
    prepared = prepare_v8_yaml_write(
        source,
        [
            V8YAMLMutation.delete(("observability", "destinations", 1)),
            V8YAMLMutation.set(
                ("observability", "destinations", 1),
                {"name": "archive", "kind": "jsonl", "path": "/tmp/日本語.jsonl"},
            ),
        ],
    )
    candidate = prepared.candidate.decode()
    destinations = yaml.safe_load(candidate)["observability"]["destinations"]

    assert [item["name"] for item in destinations] == ["first", "archive"]
    assert "# keep first comment" in candidate
    assert "# removed comment" not in candidate
    assert "\n    - name: archive\n" in candidate
    assert "  # comment belongs to local\n  local:" in candidate
    assert "retention_days: 90 # keep after list" in candidate
    assert "/tmp/日本語.jsonl" in candidate


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_newline_mode_is_preserved_for_insertions(newline: str) -> None:
    source = newline.join(
        [
            "config_version: 8",
            "observability:",
            "  local:",
            "    path: /audit.db",
            "  metric_policy:",
            "    temporality: delta",
            "",
        ]
    )
    prepared = prepare_v8_yaml_write(
        source.encode(),
        [V8YAMLMutation.set(("observability", "local", "retention_days"), 0)],
    )
    candidate = prepared.candidate.decode()

    assert prepared.newline == newline
    if newline == "\r\n":
        assert "\n" not in candidate.replace("\r\n", "")
    assert yaml.safe_load(candidate)["observability"]["local"]["retention_days"] == 0


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ("config_version: 8\nobservability: {}\nobservability: {}\n", "duplicate_mapping_key"),
        ("config_version: 8\nbase: &base {local: {}}\nobservability: *base\n", "yaml_alias_forbidden"),
        ("config_version: 8\nbase: &base {local: {}}\nobservability:\n  <<: *base\n", "yaml_alias_forbidden"),
        ("config_version: 8\nobservability: [unterminated\n", "invalid_yaml"),
    ],
)
def test_unsafe_or_invalid_yaml_is_rejected_without_echoing_values(source: str, code: str) -> None:
    hidden = "DO-NOT-ECHO-SECRET"
    source += f"# {hidden}\n"
    with pytest.raises(V8YAMLMutationError) as caught:
        prepare_v8_yaml_write(source, [])

    assert caught.value.code == code
    assert hidden not in str(caught.value)


def test_merge_key_without_alias_is_rejected() -> None:
    source = "config_version: 8\nobservability:\n  <<: {local: {}}\n"
    with pytest.raises(V8YAMLMutationError, match="merge keys") as caught:
        prepare_v8_yaml_write(source, [])
    assert caught.value.code == "yaml_merge_forbidden"


def test_non_v8_and_unsupported_paths_fail_without_mutation_values_in_error() -> None:
    with pytest.raises(V8YAMLMutationError) as wrong_version:
        prepare_v8_yaml_write("config_version: 7\nobservability: {}\n", [])
    assert wrong_version.value.code == "not_v8_configuration"

    hidden = "DO-NOT-ECHO-SECRET"
    with pytest.raises(V8YAMLMutationError) as unsupported:
        prepare_v8_yaml_write(
            "config_version: 8\nobservability: {}\n",
            [V8YAMLMutation.set(("observability", "unknown"), hidden)],
        )
    assert unsupported.value.code == "unsupported_mutation_path"
    assert hidden not in str(unsupported.value)


def test_prepared_write_is_deterministic_and_repr_is_content_safe() -> None:
    source = "config_version: 8\nobservability: {}\nsecret_elsewhere: do-not-print\n"
    mutation = V8YAMLMutation.set(("observability", "local", "retention_days"), 30)
    first = prepare_v8_yaml_write(source, [mutation], source_name="config.yaml")
    second = prepare_v8_yaml_write(source, [mutation], source_name="config.yaml")

    assert first == second
    assert first.changed is True
    assert first.expected_sha256 == hashlib.sha256(source.encode()).hexdigest()
    assert first.candidate_sha256 == hashlib.sha256(first.candidate).hexdigest()
    assert "do-not-print" not in repr(first)
    assert "30" not in repr(mutation)


def test_sequence_insertion_must_be_contiguous() -> None:
    source = "config_version: 8\nobservability: {destinations: []}\n"
    with pytest.raises(V8YAMLMutationError) as caught:
        prepare_v8_yaml_write(
            source,
            [V8YAMLMutation.set(("observability", "destinations", 2), {"name": "later", "kind": "console"})],
        )
    assert caught.value.code == "unreachable_mutation_path"
