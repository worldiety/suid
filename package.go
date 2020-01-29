/*
 * Copyright 2020 Torben Schinke
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package suid contains an alternative to the RFC 4122 UUID to improve security and serialization requirements.
// The naming causes a bit of stuttering, but it is the same like other popular packages do in this case.
//
// More importantly there is no official way to generate unsafe SUIDs, as it is very easy for UUIDs, depending
// on the version and used entropy.
package suid
