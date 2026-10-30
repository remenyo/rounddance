//! `rd-sniff`: offline 802.15.4 capture → dissect → report + pcap-out.
//!
//! File input only in this wave (no serial, no live hardware):
//! a `.pcap`/`.pcapng` recording or a saved `sniff_*.txt` text feed
//! goes through the shared dissect + fold legs, and the run lands as
//! a text report, a JSON report (session v2 snapshot with timelines),
//! and two pcap-out files (link type 195 bare frames plus the
//! radio-header variant) next to each other under `--out`.
//!
//! Usage:
//! ```text
//! rd-sniff --in w82ch25.pcap --channel 25 [--tag ch25] [--out DIR]
//!          [--net-key HEX32 --key-seq N] [--worker NAME] [--lease-seq N]
//! ```
//!
//! Exit 0 on a completed run (dissect refusals are counted, never
//! fatal); 1 on IO errors; 2 on usage errors.

use rounddance_inspect::{keys::KeySlots, pcap, sniffer::ReplayListener};
use rounddance_sniffer::{lease::lease_id_for_run, run};
use std::fs::File;
use std::io::{BufWriter, Write};

fn usage() -> ! {
    eprintln!("usage: rd-sniff --in FILE.pcap|FILE.txt --channel CH [--tag TAG] [--out DIR]");
    eprintln!("       [--net-key HEX32 --key-seq N] [--worker NAME] [--lease-seq N]");
    eprintln!("       [--text NAME] [--json NAME] [--pcap195 NAME] [--pcap-radio NAME]");
    std::process::exit(2);
}

fn fail(msg: &str) -> ! {
    eprintln!("rd-sniff: {msg}");
    std::process::exit(1);
}

fn parse_channel(s: &str) -> u8 {
    match s.parse::<u8>() {
        Ok(ch) if (11..=26).contains(&ch) => ch,
        _ => {
            eprintln!("rd-sniff: channel must be 11..=26, got {s:?}");
            std::process::exit(2);
        }
    }
}

fn parse_hex32(s: &str) -> [u8; 16] {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        eprintln!("rd-sniff: --net-key must be 32 hex chars (16 key octets)");
        std::process::exit(2);
    }
    let mut key = [0u8; 16];
    for (i, k) in key.iter_mut().enumerate() {
        *k = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or_else(|_| usage());
    }
    key
}

fn file_stem(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    match base.rfind('.') {
        Some(i) => String::from(&base[..i]),
        None => String::from(base),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut input: Option<String> = None;
    let mut channel: Option<u8> = None;
    let mut tag: Option<String> = None;
    let mut out = String::from(".");
    let mut net_key: Option<[u8; 16]> = None;
    let mut key_seq: u8 = 0;
    let mut worker = String::from("w1-offline");
    let mut lease_seq: u32 = 0;
    let mut text_name: Option<String> = None;
    let mut json_name: Option<String> = None;
    let mut pcap195_name: Option<String> = None;
    let mut pcap_radio_name: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => {
                i += 1;
                input = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--channel" => {
                i += 1;
                channel = Some(parse_channel(
                    &args.get(i).cloned().unwrap_or_else(|| usage()),
                ));
            }
            "--tag" => {
                i += 1;
                tag = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--out" => {
                i += 1;
                out = args.get(i).cloned().unwrap_or_else(|| usage());
            }
            "--net-key" => {
                i += 1;
                net_key = Some(parse_hex32(
                    &args.get(i).cloned().unwrap_or_else(|| usage()),
                ));
            }
            "--key-seq" => {
                i += 1;
                key_seq = args
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| usage())
                    .parse()
                    .unwrap_or_else(|_| usage());
            }
            "--worker" => {
                i += 1;
                worker = args.get(i).cloned().unwrap_or_else(|| usage());
            }
            "--lease-seq" => {
                i += 1;
                lease_seq = args
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| usage())
                    .parse()
                    .unwrap_or_else(|_| usage());
            }
            "--text" => {
                i += 1;
                text_name = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--json" => {
                i += 1;
                json_name = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--pcap195" => {
                i += 1;
                pcap195_name = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--pcap-radio" => {
                i += 1;
                pcap_radio_name = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            _ => usage(),
        }
        i += 1;
    }
    let input = input.unwrap_or_else(|| usage());
    let channel = channel.unwrap_or_else(|| usage());
    let tag = tag.unwrap_or_else(|| file_stem(&input));
    let lease = lease_id_for_run(&worker, &tag, channel, lease_seq);
    let mut keys = KeySlots::new();
    if let Some(k) = net_key {
        keys.set_network_key(k, key_seq);
    }

    let rep = if input.ends_with(".pcap") || input.ends_with(".pcapng") {
        let mut f = File::open(&input).unwrap_or_else(|e| fail(&format!("open {input}: {e}")));
        let packets =
            pcap::read_all(&mut f).unwrap_or_else(|e| fail(&format!("ingest {input}: {e:?}")));
        let non_154 = packets
            .iter()
            .filter(|p| {
                p.linktype != pcap::LINKTYPE_IEEE802_15_4
                    && p.linktype != pcap::LINKTYPE_IEEE802_15_4_NOFCS
            })
            .count();
        if non_154 > 0 {
            eprintln!("rd-sniff: note: {non_154} packet(s) with non-15.4 linktype (dissected as 15.4 anyway)");
        }
        run::run_packets(&packets, channel, &keys, &tag, lease)
    } else {
        let mut li = ReplayListener::open(&input, channel)
            .unwrap_or_else(|e| fail(&format!("replay {input}: {e}")));
        run::run_listener(&mut li, channel, &keys, &tag, lease)
    };

    let text_path = format!(
        "{out}/{}",
        text_name.unwrap_or_else(|| format!("{tag}.report.txt"))
    );
    let json_path = format!(
        "{out}/{}",
        json_name.unwrap_or_else(|| format!("{tag}.report.json"))
    );
    let p195_path = format!(
        "{out}/{}",
        pcap195_name.unwrap_or_else(|| format!("{tag}.195.pcap"))
    );
    let radio_path = format!(
        "{out}/{}",
        pcap_radio_name.unwrap_or_else(|| format!("{tag}.radio.pcap"))
    );

    let mut tf = BufWriter::new(
        File::create(&text_path).unwrap_or_else(|e| fail(&format!("create {text_path}: {e}"))),
    );
    tf.write_all(run::text_report(&rep).as_bytes())
        .unwrap_or_else(|e| fail(&format!("write {text_path}: {e}")));
    let mut jf = BufWriter::new(
        File::create(&json_path).unwrap_or_else(|e| fail(&format!("create {json_path}: {e}"))),
    );
    jf.write_all(run::json_report(&rep).as_bytes())
        .unwrap_or_else(|e| fail(&format!("write {json_path}: {e}")));
    let mut p195 = BufWriter::new(
        File::create(&p195_path).unwrap_or_else(|e| fail(&format!("create {p195_path}: {e}"))),
    );
    run::write_pcap_195(&rep, &mut p195)
        .unwrap_or_else(|e| fail(&format!("write {p195_path}: {e}")));
    let mut prad = BufWriter::new(
        File::create(&radio_path).unwrap_or_else(|e| fail(&format!("create {radio_path}: {e}"))),
    );
    run::write_pcap_radio(&rep, &mut prad)
        .unwrap_or_else(|e| fail(&format!("write {radio_path}: {e}")));

    let mut lease_hex = [0u8; 16];
    rounddance_sniffer::lease::lease_id_hex(lease, &mut lease_hex);
    println!(
        "run: lease={} tag={tag} channel={channel} frames={} dissect_errors={} listener_errors={}",
        String::from_utf8_lossy(&lease_hex),
        rep.frames.len(),
        rep.dissect_errors,
        rep.listener_errors,
    );
}
