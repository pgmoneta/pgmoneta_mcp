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

pub struct Utility;

impl Utility {
    pub fn format_file_size(size: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        const TB: u64 = GB * 1024;

        if size < KB {
            format!("{size} B")
        } else if size < MB {
            format!("{:.2} KB", size as f64 / KB as f64)
        } else if size < GB {
            format!("{:.2} MB", size as f64 / MB as f64)
        } else if size < TB {
            format!("{:.2} GB", size as f64 / GB as f64)
        } else {
            format!("{:.2} TB", size as f64 / TB as f64)
        }
    }
}
