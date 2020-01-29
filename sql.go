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

package suid

import "fmt"

// Scan implements sql.Scanner so SUIDs can be read from databases.
// Currently, database types that map to string and []byte are supported. Please consult your
// database documentation and try to define your column type as efficient as possible, e.g. BINARY(32).
func (id *SUID) Scan(src interface{}) error {
	switch src := src.(type) {
	case nil:
		return nil

	case string:
		// if an empty SUID comes from a table, we return a null UUID
		if src == "" {
			return nil
		}

		// see Parse for required string format
		u, err := Parse(src)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		*id = u

	case []byte:
		// if an empty SUID comes from a table, we return a null UUID
		if len(src) == 0 {
			return nil
		}

		if len(src) != Size {
			return id.Scan(string(src))
		}

		copy((*id)[:], src)

	default:
		return fmt.Errorf("scan: unable to scan type %T into Secure SUID", src)
	}

	return nil
}
