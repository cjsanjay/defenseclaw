// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package schemas embeds DefenseClaw's canonical public schemas for consumers
// that cannot rely on a repository checkout at runtime.
package schemas

import _ "embed"

//go:embed config/v8/defenseclaw-config.schema.json
var defenseClawConfigV8Schema []byte

// DefenseClawConfigV8Schema returns a copy of the exact checked-in canonical v8
// configuration schema bytes. Callers cannot mutate the process-wide embed.
func DefenseClawConfigV8Schema() []byte {
	return append([]byte(nil), defenseClawConfigV8Schema...)
}
