//! Generate public synthetic inputs using normal writer APIs.
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .unwrap_or_else(|| "corpus".into()),
    );
    for name in ["ewf_read", "ewf_catalog"] {
        std::fs::create_dir_all(root.join(name))?;
    }
    let temporary = tempfile::tempdir()?;
    let input: Vec<u8> = (0..65536).map(|n| (n * 17 + n / 97) as u8).collect();
    for (n, format) in [
        ewf_image::WriteFormat::Ewf1Physical,
        ewf_image::WriteFormat::Ewf2Physical,
        ewf_image::WriteFormat::Ewf2Logical,
    ]
    .into_iter()
    .enumerate()
    {
        let path = temporary.path().join(format!("seed{n}.E01"));
        let mut writer = ewf_image::EwfWriter::create(
            &path,
            ewf_image::WriteOptions {
                format,
                ..Default::default()
            },
        )?;
        writer.write_all(&input)?;
        writer.finish()?;
        std::fs::copy(path, root.join("ewf_read").join(format!("seed{n}")))?;
    }
    write_catalog_seeds(&root, temporary.path())?;
    Ok(())
}

fn write_catalog_seeds(
    root: &std::path::Path,
    temporary: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let lines = [
        "5",
        "rec",
        "tb",
        "4096",
        "",
        "perm",
        "0\t1",
        "pt",
        "0\t0",
        "10",
        "",
        "srce",
        "0\t1",
        "id",
        "0\t0",
        "0",
        "",
        "sub",
        "0\t1",
        "id",
        "0\t0",
        "0",
        "",
        "entry",
        "0\t1",
        "id\tp\tn\tls\tbe\tdu\topr",
        "26\t1",
        "1\td\troot\t0\t\t\t",
        "26\t2",
        "2\td\tfolder/name\t4\t1 0 4\t\t",
        "26\t0",
        "3\tf\tpart\\name·stream\t8\t2 4 4 S 0 4\t\t",
        "26\t0",
        "4\tf\tduplicate.bin\t4\t\t4\t67108864",
        "",
    ];
    let units: Vec<u16> = (lines.join("\n") + "\n").encode_utf16().collect();
    let needle: Vec<u16> = "part\\name·stream".encode_utf16().collect();
    let name_start = units
        .windows(needle.len())
        .position(|window| window == needle)
        .ok_or("catalog seed name missing")?;
    for (suffix, catalog) in [
        ("normal", units.clone()),
        ("unpaired-name", {
            let mut changed = units.clone();
            changed[name_start] = 0xd800;
            changed
        }),
    ] {
        let catalog: Vec<u8> = catalog.into_iter().flat_map(u16::to_le_bytes).collect();
        for (kind, ewf1) in [(0_u8, true), (1_u8, false)] {
            let parsed = ewf_image::parse_single_files_for_fuzzing(&catalog, ewf1)?;
            assert_eq!(parsed.root.children[0].children.len(), 2);
            assert_eq!(
                parsed.root.children[0].children[0].name_utf16.is_some(),
                suffix == "unpaired-name"
            );
            let mut seed = vec![kind];
            seed.extend_from_slice(&catalog);
            std::fs::write(
                root.join("ewf_catalog")
                    .join(format!("catalog-{kind}-{suffix}")),
                seed,
            )?;
        }
    }

    let mut state = 0x1234_5678_u32;
    let large: Vec<u8> = (0..110_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    for (index, format, extension) in [
        (0_u8, ewf_image::WriteFormat::Ewf1Logical, "L"),
        (1_u8, ewf_image::WriteFormat::Ewf2Logical, "Lx"),
    ] {
        for (split, payload) in [(false, &large[..4096]), (true, large.as_slice())] {
            let path = temporary.join(format!("catalog-{index}-{split}.{extension}01"));
            let mut writer = ewf_image::LogicalWriter::create(
                &path,
                ewf_image::WriteOptions {
                    format,
                    compression: ewf_image::WriteCompression::Zlib,
                    maximum_segment_size: split.then_some(65_536),
                    ..ewf_image::WriteOptions::default()
                },
            )?;
            let folder = writer.add_directory(
                1,
                ewf_image::LogicalEntryMetadata {
                    name: "folder/name".into(),
                    ..Default::default()
                },
            )?;
            let mut file_input = payload;
            writer.add_file(
                folder,
                ewf_image::LogicalEntryMetadata {
                    name: "part\\name·stream".into(),
                    ..Default::default()
                },
                payload.len() as u64,
                &mut file_input,
            )?;
            let mut empty_input: &[u8] = &[];
            writer.add_file(
                folder,
                ewf_image::LogicalEntryMetadata {
                    name: "empty".into(),
                    ..Default::default()
                },
                0,
                &mut empty_input,
            )?;
            let result = writer.finish()?;
            assert_eq!(result.segment_paths.len() > 1, split);
            let image = ewf_image::Image::open(&result.segment_paths[0])?;
            let root_entry = image.root_file_entry().unwrap();
            assert_eq!(root_entry.children.len(), 1);
            let file_entry = &root_entry.children[0].children[0];
            let mut check = [0; 64];
            let check_len = check.len();
            assert_eq!(
                image.read_single_file_at_strict(file_entry, &mut check, 0)?,
                check_len
            );
            assert_eq!(&check, &payload[..check_len]);
            if split {
                assert_eq!(
                    image.read_single_file_at_strict(
                        file_entry,
                        &mut check,
                        payload.len() as u64 - check_len as u64,
                    )?,
                    check_len
                );
                assert_eq!(&check, &payload[payload.len() - check_len..]);
            }

            let mut seed = vec![if split { index + 4 } else { index + 2 }];
            if split {
                seed.push(u8::try_from(result.segment_paths.len())?);
            }
            for segment in result.segment_paths {
                let bytes = std::fs::read(segment)?;
                if split {
                    seed.extend_from_slice(&u32::try_from(bytes.len())?.to_le_bytes());
                }
                seed.extend_from_slice(&bytes);
            }
            assert!(seed.len() <= 1024 * 1024);
            std::fs::write(
                root.join("ewf_catalog")
                    .join(format!("image-{index}-{split}")),
                seed,
            )?;
        }
    }
    Ok(())
}
