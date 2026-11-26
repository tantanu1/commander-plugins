//! S3 XML responses (roxmltree) + the one request body we send.
use roxmltree::{Document, Node};

#[derive(Debug, Default, PartialEq)]
pub struct Obj {
    pub key: String,
    pub size: u64,
    /// unix ns, `None` = unknown.
    pub mtime: Option<i64>,
}

/// One ListObjectsV2 page.
#[derive(Debug, Default, PartialEq)]
pub struct Page {
    /// Full common prefixes (`dir/sub/`).
    pub dirs: Vec<String>,
    pub files: Vec<Obj>,
    /// Continuation token when truncated.
    pub next: Option<String>,
}

fn doc(xml: &str) -> Result<Document<'_>, String> {
    Document::parse(xml).map_err(|e| format!("bad S3 XML: {e}"))
}

fn text<'a>(n: Node<'a, '_>, tag: &str) -> Option<&'a str> {
    n.children().find(|c| c.has_tag_name(tag))?.text()
}

fn all<'a, 'i>(n: Node<'a, 'i>, tag: &'static str) -> impl Iterator<Item = Node<'a, 'i>> {
    n.children().filter(move |c| c.has_tag_name(tag))
}

pub fn list_objects(xml: &str) -> Result<Page, String> {
    let d = doc(xml)?;
    let r = d.root_element();
    let files = all(r, "Contents")
        .filter_map(|c| {
            Some(Obj {
                key: text(c, "Key")?.to_owned(),
                size: text(c, "Size").and_then(|s| s.parse().ok()).unwrap_or(0),
                mtime: text(c, "LastModified").and_then(crate::sign::parse_iso),
            })
        })
        .collect();
    let dirs = all(r, "CommonPrefixes")
        .filter_map(|c| text(c, "Prefix").map(str::to_owned))
        .collect();
    let next = (text(r, "IsTruncated") == Some("true"))
        .then(|| text(r, "NextContinuationToken").map(str::to_owned))
        .flatten();
    Ok(Page { dirs, files, next })
}

/// ListBuckets: (name, creation time).
pub fn buckets(xml: &str) -> Result<Vec<Obj>, String> {
    let d = doc(xml)?;
    let Some(list) = d
        .root_element()
        .children()
        .find(|c| c.has_tag_name("Buckets"))
    else {
        return Ok(Vec::new());
    };
    Ok(all(list, "Bucket")
        .filter_map(|b| {
            Some(Obj {
                key: text(b, "Name")?.to_owned(),
                size: 0,
                mtime: text(b, "CreationDate").and_then(crate::sign::parse_iso),
            })
        })
        .collect())
}

pub fn upload_id(xml: &str) -> Result<String, String> {
    let d = doc(xml)?;
    text(d.root_element(), "UploadId")
        .map(str::to_owned)
        .ok_or_else(|| "S3: no UploadId in response".to_owned())
}

/// `<Error>` body -> (Code, Message). Also catches 200-with-error (CopyObject, Complete).
pub fn error(xml: &str) -> Option<(String, String)> {
    let d = Document::parse(xml).ok()?;
    let r = d.root_element();
    r.has_tag_name("Error").then(|| {
        (
            text(r, "Code").unwrap_or("Unknown").to_owned(),
            text(r, "Message").unwrap_or_default().to_owned(),
        )
    })
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// CompleteMultipartUpload body; part numbers are 1-based in order.
pub fn complete_body(etags: &[String]) -> String {
    let parts: String = etags
        .iter()
        .enumerate()
        .map(|(i, e)| {
            format!(
                "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
                i + 1,
                escape(e)
            )
        })
        .collect();
    format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>")
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = r#"xmlns="http://s3.amazonaws.com/doc/2006-03-01/""#;

    #[test]
    fn list_page_with_dirs_files_and_token() {
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult {NS}><Name>b</Name><Prefix>d/</Prefix><KeyCount>3</KeyCount>
<IsTruncated>true</IsTruncated><NextContinuationToken>tok/+=</NextContinuationToken>
<Contents><Key>d/</Key><LastModified>2009-10-12T17:50:30.000Z</LastModified><Size>0</Size></Contents>
<Contents><Key>d/a &amp; b.txt</Key><LastModified>2009-10-12T17:50:30.000Z</LastModified><ETag>"x"</ETag><Size>11</Size></Contents>
<CommonPrefixes><Prefix>d/sub/</Prefix></CommonPrefixes></ListBucketResult>"#
        );
        let p = list_objects(&xml).unwrap();
        assert_eq!(p.dirs, ["d/sub/"]);
        assert_eq!(p.files.len(), 2);
        assert_eq!(p.files[1].key, "d/a & b.txt");
        assert_eq!(p.files[1].size, 11);
        assert_eq!(p.files[1].mtime, Some(1_255_369_830_000_000_000));
        assert_eq!(p.next.as_deref(), Some("tok/+="));
        let last = list_objects(&format!(
            "<ListBucketResult {NS}><IsTruncated>false</IsTruncated></ListBucketResult>"
        ))
        .unwrap();
        assert_eq!(last, Page::default());
        assert!(list_objects("<oops").is_err());
    }

    #[test]
    fn buckets_upload_id_errors() {
        let xml = format!(
            "<ListAllMyBucketsResult {NS}><Owner><ID>o</ID></Owner><Buckets>\
             <Bucket><Name>one</Name><CreationDate>2009-10-12T17:50:30.000Z</CreationDate></Bucket>\
             <Bucket><Name>two</Name></Bucket></Buckets></ListAllMyBucketsResult>"
        );
        let b = buckets(&xml).unwrap();
        assert_eq!(
            b.iter().map(|o| o.key.as_str()).collect::<Vec<_>>(),
            ["one", "two"]
        );
        let id = format!(
            "<InitiateMultipartUploadResult {NS}><Bucket>b</Bucket><Key>k</Key>\
             <UploadId>VXBsb2Fk</UploadId></InitiateMultipartUploadResult>"
        );
        assert_eq!(upload_id(&id).unwrap(), "VXBsb2Fk");
        let e = "<Error><Code>NoSuchKey</Code><Message>gone</Message></Error>";
        assert_eq!(error(e), Some(("NoSuchKey".into(), "gone".into())));
        assert_eq!(error(&id), None);
    }

    #[test]
    fn complete_body_numbers_parts() {
        let b = complete_body(&["\"a\"".into(), "\"b&\"".into()]);
        assert_eq!(
            b,
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"a\"</ETag></Part>\
             <Part><PartNumber>2</PartNumber><ETag>\"b&amp;\"</ETag></Part></CompleteMultipartUpload>"
        );
    }
}
