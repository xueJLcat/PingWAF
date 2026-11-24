use super::{ApiError, Snapshot};
use printpdf::{
    Color, IndirectFontRef, Mm, PdfDocument, PdfDocumentReference,
    PdfLayerReference, Rgb,
};
use std::{collections::BTreeMap, io::Cursor};

const FONT: &[u8] =
    include_bytes!("../../../assets/report-font/WenQuanYiMicroHei.ttf");
const MAX_BYTES: usize = 12 * 1024 * 1024;

#[derive(Default)]
struct Totals {
    values: [Option<i64>; 3],
    partial: bool,
}
impl Totals {
    fn add(&mut self, row: &super::MetricRow) {
        for (sum, value) in self.values.iter_mut().zip([
            row.requests,
            row.blocked,
            row.challenged,
        ]) {
            if let Some(n) = value {
                *sum = Some(sum.unwrap_or(0) + n);
            }
        }
        self.partial |= !row.covered;
    }
    fn number(&self, index: usize) -> String {
        match self.values[index] {
            Some(n) if n != 0 || !self.partial => {
                format!("{n}{}", if self.partial { "*" } else { "" })
            },
            _ => "缺失".into(),
        }
    }
}

fn field(s: &str) -> String {
    // Spreadsheet applications interpret leading formulas even in quoted CSV.
    let prefix = if s.trim_start().starts_with(['=', '+', '-', '@']) {
        "'"
    } else {
        ""
    };
    format!("\"{prefix}{}\"", s.replace('"', "\"\""))
}
fn csv_row(output: &mut String, fields: &[&str]) {
    output.push_str(
        &fields
            .iter()
            .map(|s| field(s))
            .collect::<Vec<_>>()
            .join(","),
    );
    output.push_str("\r\n");
}

struct Pages {
    doc: PdfDocumentReference,
    font: IndirectFontRef,
    layer: PdfLayerReference,
    y: f32,
    page: u32,
}
impl Pages {
    fn new() -> Result<Self, ApiError> {
        let (doc, p, l) = PdfDocument::new(
            "PingWAF 防护报告",
            Mm(210.),
            Mm(297.),
            "防护报告",
        );
        let font = doc.add_external_font(Cursor::new(FONT)).map_err(|_| {
            ApiError::Internal("report font unavailable".into())
        })?;
        let layer = doc.get_page(p).get_layer(l);
        let mut pages = Self {
            doc,
            font,
            layer,
            y: 0.,
            page: 1,
        };
        pages.header();
        Ok(pages)
    }
    fn header(&mut self) {
        self.layer
            .set_fill_color(Color::Rgb(Rgb::new(0.10, 0.25, 0.32, None)));
        self.layer.use_text(
            "PingWAF   /   防护报告",
            18.,
            Mm(17.),
            Mm(274.),
            &self.font,
        );
        self.layer.use_text(
            format!("第 {} 页", self.page),
            9.,
            Mm(169.),
            Mm(13.),
            &self.font,
        );
        self.y = 259.;
    }
    fn space(&mut self, needed: f32) {
        if self.y - needed < 23. {
            self.page += 1;
            let (p, l) = self.doc.add_page(Mm(210.), Mm(297.), "报告");
            self.layer = self.doc.get_page(p).get_layer(l);
            self.header();
        }
    }
    fn heading(&mut self, s: &str) {
        self.space(20.);
        self.y -= 3.;
        self.layer.use_text(s, 13., Mm(17.), Mm(self.y), &self.font);
        self.y -= 9.;
    }
    fn line(&mut self, s: &str) {
        // At 9pt even full-width CJK glyphs fit within the 176mm content area.
        let chars: Vec<_> = s.chars().filter(|c| !c.is_control()).collect();
        for part in chars.chunks(53) {
            self.space(6.);
            self.layer.use_text(
                part.iter().collect::<String>(),
                9.,
                Mm(17.),
                Mm(self.y),
                &self.font,
            );
            self.y -= 5.6;
        }
    }
    fn table(&mut self, label: &str, t: &Totals) {
        if self.y < 30. {
            self.space(15.);
            self.columns();
        }
        self.layer
            .use_text(label, 9., Mm(17.), Mm(self.y), &self.font);
        for (i, x) in [115., 143., 170.].into_iter().enumerate() {
            self.layer
                .use_text(t.number(i), 9., Mm(x), Mm(self.y), &self.font);
        }
        self.y -= 6.;
    }
    fn columns(&mut self) {
        for (text, x) in [
            ("当地时间", 17.),
            ("请求", 115.),
            ("拦截", 143.),
            ("挑战", 170.),
        ] {
            self.layer.use_text(text, 9., Mm(x), Mm(self.y), &self.font);
        }
        self.y -= 7.;
    }
}

pub(super) fn render(s: &Snapshot) -> Result<(Vec<u8>, Vec<u8>), ApiError> {
    let mut csv = String::from("\u{feff}");
    csv_row(
        &mut csv,
        &[
            "分组",
            "站点 UUID",
            "站点或类别",
            "时间桶 UTC",
            "当地时间",
            "时区",
            "指标",
            "值",
            "单位",
            "覆盖",
        ],
    );
    let mut total = Totals::default();
    let mut sites = BTreeMap::new();
    let mut trend = BTreeMap::new();
    for row in &s.metrics {
        let instant = row.bucket.to_rfc3339();
        let id = row.site.to_string();
        let coverage = if row.covered {
            "完整"
        } else {
            "部分或缺失"
        };
        for (metric, value, unit) in [
            ("请求量", row.requests, "条访问日志"),
            ("拦截量", row.blocked, "个事件"),
            ("挑战量", row.challenged, "个事件"),
        ] {
            let number = value.map(|n| n.to_string()).unwrap_or_default();
            csv_row(
                &mut csv,
                &[
                    "站点时间桶",
                    &id,
                    &row.domain,
                    &instant,
                    &row.local_time,
                    &s.selection.timezone,
                    metric,
                    &number,
                    unit,
                    coverage,
                ],
            );
        }
        total.add(row);
        sites
            .entry((row.domain.as_str(), row.site))
            .or_insert_with(Totals::default)
            .add(row);
        trend
            .entry((row.bucket, row.local_time.as_str()))
            .or_insert_with(Totals::default)
            .add(row);
    }
    for (category, n) in &s.categories {
        csv_row(
            &mut csv,
            &[
                "攻击类别",
                "",
                category,
                "",
                "",
                &s.selection.timezone,
                "安全事件",
                &n.to_string(),
                "个事件",
                if total.partial {
                    "部分或缺失"
                } else {
                    "完整"
                },
            ],
        );
    }
    let mut p = Pages::new()?;
    p.line(&format!(
        "统计范围  {} 至 {}（UTC）",
        s.selection.from.format("%Y-%m-%d %H:%M"),
        s.selection.to.format("%Y-%m-%d %H:%M")
    ));
    p.line(&format!(
        "显示时区  {}     快照生成于 {} UTC",
        s.selection.timezone,
        s.generated_at.format("%Y-%m-%d %H:%M:%S")
    ));
    p.heading("防护概览");
    p.line(&format!(
        "请求量 {} 条     拦截 {} 个事件     挑战 {} 个事件",
        total.number(0),
        total.number(1),
        total.number(2)
    ));
    p.line("请求量按访问日志条数统计，拦截和挑战按安全事件条数统计。一次请求可能产生多个事件。");
    p.line(&format!("缺少完整采集证据的站点时间桶 {} 个。星号表示已观测数量；空白 CSV 值表示缺失。",s.metrics.iter().filter(|r|!r.covered).count()));
    p.heading("重点站点");
    let mut ranking: Vec<_> = sites.into_iter().collect();
    ranking.sort_by_key(|(id, t)| {
        (std::cmp::Reverse(t.values[0].unwrap_or(0)), *id)
    });
    for ((domain, id), t) in ranking {
        p.line(&format!("{domain}  ·  {id}"));
        p.line(&format!(
            "请求 {}     拦截 {}     挑战 {}",
            t.number(0),
            t.number(1),
            t.number(2)
        ));
    }
    p.heading("攻击类别");
    if s.categories.is_empty() {
        p.line(if total.partial {
            "当前数据范围内未观测到分类事件，存在采集缺口。"
        } else {
            "未记录安全事件。"
        });
    }
    for (category, count) in &s.categories {
        p.line(&format!("{category}    {count} 个事件"));
    }
    p.heading("处置趋势");
    p.columns();
    for ((_, label), t) in trend {
        p.table(label, &t);
    }
    let pdf = p
        .doc
        .save_to_bytes()
        .map_err(|_| ApiError::Internal("PDF rendering failed".into()))?;
    if pdf.len().max(csv.len()) > MAX_BYTES {
        return Err(ApiError::BadRequest("report exceeds size limit".into()));
    }
    Ok((pdf, csv.into_bytes()))
}
