// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Elijah Brigham
//
// This file is changed from ebrig/ewf-image (https://github.com/ebrig/ewf-image), whose code is
// under the Apache License 2.0 (LICENSE-APACHE).
//
// SPDX-License-Identifier: (RPL-1.5 OR AGPL-3.0-only) AND Apache-2.0
//
// You may instead use this file under the GNU Affero General Public License, version 3 only
// (LICENSE-AGPL-3.0). The notice below is for the RPL.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

use std::borrow::Cow;

use crate::types::HeaderDateFormat;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeaderDateTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

pub(crate) fn format_header_date_value(value: &str, date_format: HeaderDateFormat) -> Cow<'_, str> {
    HeaderDateTime::parse(value).map_or(Cow::Borrowed(value), |date_time| {
        Cow::Owned(date_time.format(date_format))
    })
}

pub(crate) fn format_ewf1_header_date_value(value: &str) -> Cow<'_, str> {
    HeaderDateTime::parse(value).map_or(Cow::Borrowed(value), |date_time| {
        Cow::Owned(date_time.format_ewf1_header())
    })
}

pub(crate) fn format_ewf1_header2_date_value(value: &str) -> Cow<'_, str> {
    HeaderDateTime::parse(value).map_or(Cow::Borrowed(value), |date_time| {
        Cow::Owned(date_time.unix_timestamp().to_string())
    })
}

pub(crate) fn format_xheader_date_value(value: &str) -> Cow<'_, str> {
    HeaderDateTime::parse(value).map_or(Cow::Borrowed(value), |date_time| {
        Cow::Owned(date_time.format(HeaderDateFormat::Ctime))
    })
}

impl HeaderDateTime {
    fn parse(value: &str) -> Option<Self> {
        parse_legacy_date_time(value)
            .or_else(|| parse_iso8601_date_time(value))
            .or_else(|| parse_unix_timestamp_date_time(value))
            .or_else(|| parse_ctime_date_time(value))
    }

    fn format(self, date_format: HeaderDateFormat) -> String {
        match date_format {
            HeaderDateFormat::DayMonth => format!(
                "{:02}/{:02}/{:04} {:02}:{:02}:{:02}",
                self.day, self.month, self.year, self.hour, self.minute, self.second
            ),
            HeaderDateFormat::MonthDay => format!(
                "{:02}/{:02}/{:04} {:02}:{:02}:{:02}",
                self.month, self.day, self.year, self.hour, self.minute, self.second
            ),
            HeaderDateFormat::Iso8601 => format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                self.year, self.month, self.day, self.hour, self.minute, self.second
            ),
            HeaderDateFormat::Ctime => format!(
                "{} {} {:>2} {:02}:{:02}:{:02} {:04}",
                weekday_name(self.year, self.month, self.day),
                month_name(self.month),
                self.day,
                self.hour,
                self.minute,
                self.second,
                self.year
            ),
        }
    }

    fn format_ewf1_header(self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    fn unix_timestamp(self) -> i64 {
        let days_before_year = days_before_year(i64::from(self.year));
        let days_before_month = days_before_month(self.year, self.month);
        let days = days_before_year + i64::from(days_before_month) + i64::from(self.day - 1);
        days * 86_400
            + i64::from(self.hour) * 3_600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }

    fn from_unix_timestamp(timestamp: i64) -> Option<Self> {
        if timestamp < 0 {
            return None;
        }

        let mut remaining_days = timestamp / 86_400;
        let seconds_of_day = timestamp % 86_400;
        let mut year = 1970_u16;
        loop {
            let year_days = if is_leap_year(year) { 366 } else { 365 };
            if remaining_days < year_days {
                break;
            }
            remaining_days -= year_days;
            year = year.checked_add(1)?;
        }

        let mut month = 1_u8;
        loop {
            let month_days = i64::from(days_in_month(year, month));
            if remaining_days < month_days {
                break;
            }
            remaining_days -= month_days;
            month = month.checked_add(1)?;
        }

        Some(Self {
            year,
            month,
            day: u8::try_from(remaining_days + 1).ok()?,
            hour: u8::try_from(seconds_of_day / 3_600).ok()?,
            minute: u8::try_from(seconds_of_day % 3_600 / 60).ok()?,
            second: u8::try_from(seconds_of_day % 60).ok()?,
        })
    }
}

fn parse_legacy_date_time(value: &str) -> Option<HeaderDateTime> {
    let mut parts = value.split_whitespace();
    let date_time = HeaderDateTime {
        year: parts.next()?.parse().ok()?,
        month: parts.next()?.parse().ok()?,
        day: parts.next()?.parse().ok()?,
        hour: parts.next()?.parse().ok()?,
        minute: parts.next()?.parse().ok()?,
        second: parts.next()?.parse().ok()?,
    };
    if parts.next().is_some() {
        return None;
    }
    date_time.validate().then_some(date_time)
}

fn parse_iso8601_date_time(value: &str) -> Option<HeaderDateTime> {
    let value = value.strip_suffix('Z').unwrap_or(value);
    let (date, time) = value.split_once('T')?;
    let mut date_parts = date.split('-');
    let mut time_parts = time.split(':');
    let date_time = HeaderDateTime {
        year: date_parts.next()?.parse().ok()?,
        month: date_parts.next()?.parse().ok()?,
        day: date_parts.next()?.parse().ok()?,
        hour: time_parts.next()?.parse().ok()?,
        minute: time_parts.next()?.parse().ok()?,
        second: time_parts.next()?.parse().ok()?,
    };
    if date_parts.next().is_some() || time_parts.next().is_some() {
        return None;
    }
    date_time.validate().then_some(date_time)
}

fn parse_unix_timestamp_date_time(value: &str) -> Option<HeaderDateTime> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    HeaderDateTime::from_unix_timestamp(value.parse().ok()?)
}

fn parse_ctime_date_time(value: &str) -> Option<HeaderDateTime> {
    let mut parts = value.split_whitespace();
    let weekday = parts.next()?;
    if !is_weekday_name(weekday) {
        return None;
    }
    let month = parse_month_name(parts.next()?)?;
    let day = parts.next()?.parse().ok()?;
    let mut time_parts = parts.next()?.split(':');
    let date_time = HeaderDateTime {
        year: parts.next()?.parse().ok()?,
        month,
        day,
        hour: time_parts.next()?.parse().ok()?,
        minute: time_parts.next()?.parse().ok()?,
        second: time_parts.next()?.parse().ok()?,
    };
    if time_parts.next().is_some() || parts.count() > 2 {
        return None;
    }
    date_time.validate().then_some(date_time)
}

impl HeaderDateTime {
    fn validate(self) -> bool {
        self.year > 0
            && (1..=12).contains(&self.month)
            && self.day >= 1
            && self.day <= days_in_month(self.year, self.month)
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 60
    }
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && !year.is_multiple_of(100) || year.is_multiple_of(400)
}

fn days_before_year(year: i64) -> i64 {
    let previous_year = year - 1;
    365 * (year - 1970) + previous_year / 4 - previous_year / 100 + previous_year / 400
        - (1969 / 4 - 1969 / 100 + 1969 / 400)
}

fn days_before_month(year: u16, month: u8) -> u16 {
    let mut days = 0;
    for candidate_month in 1..month {
        days += u16::from(days_in_month(year, candidate_month));
    }
    days
}

fn month_name(month: u8) -> &'static str {
    match month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "",
    }
}

fn parse_month_name(month: &str) -> Option<u8> {
    Some(match month {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

fn weekday_name(year: u16, month: u8, day: u8) -> &'static str {
    match weekday_index(year, month, day) {
        0 => "Sun",
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        6 => "Sat",
        _ => "",
    }
}

fn is_weekday_name(weekday: &str) -> bool {
    matches!(
        weekday,
        "Sun" | "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat"
    )
}

fn weekday_index(year: u16, month: u8, day: u8) -> u8 {
    let mut month = i32::from(month);
    let mut year = i32::from(year);
    if month < 3 {
        month += 12;
        year -= 1;
    }
    let century = year / 100;
    let year_of_century = year % 100;
    let h = (i32::from(day)
        + (13 * (month + 1)) / 5
        + year_of_century
        + year_of_century / 4
        + century / 4
        + 5 * century)
        % 7;
    ((h + 6) % 7) as u8
}
