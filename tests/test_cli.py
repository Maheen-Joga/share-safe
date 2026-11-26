import io
import json
import os
import stat

import pytest

from share_safe.cli import main

from . import helpers as h


@pytest.fixture
def log(tmp_path):
    f = tmp_path / "error.log"
    f.write_text(f"user maria@gmail.com from 84.163.22.17\nGITHUB_TOKEN={h.GITHUB}\n", encoding="utf-8")
    return f


def test_redact_is_the_default_command(log, capsys):
    assert main([str(log)]) == 0
    out, err = capsys.readouterr()
    assert out == "user <EMAIL_1> from <IP_1>\nGITHUB_TOKEN=<GITHUB_TOKEN_1>\n"
    assert "replaced 3 values" in err and "read it once before sharing" in err


def test_redact_from_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("ping 84.163.22.17\n"))
    assert main(["-q"]) == 0
    assert capsys.readouterr().out == "ping <IP_1>\n"


def test_output_file_and_private_map_then_restore(log, tmp_path, capsys):
    out, m = tmp_path / "safe.log", tmp_path / "map.json"
    assert main(["redact", str(log), "-o", str(out), "--map", str(m), "-q"]) == 0
    assert stat.S_IMODE(os.stat(m).st_mode) == 0o600
    assert json.loads(m.read_text())["<GITHUB_TOKEN_1>"] == h.GITHUB
    assert main(["restore", str(out), "--map", str(m)]) == 0
    assert capsys.readouterr().out == log.read_text()


def test_map_keeps_numbering_across_runs(tmp_path, capsys):
    a, b, m = tmp_path / "a.log", tmp_path / "b.log", tmp_path / "m.json"
    a.write_text("maria@gmail.com\n")
    b.write_text("tom@gmx.de maria@gmail.com\n")
    main([str(a), "--map", str(m), "-q"])
    capsys.readouterr()
    main([str(b), "--map", str(m), "-q"])
    assert capsys.readouterr().out == "<EMAIL_2> <EMAIL_1>\n"


def test_several_files_are_labelled(tmp_path, capsys):
    a, b = tmp_path / "a.log", tmp_path / "b.log"
    a.write_text("maria@gmail.com\n")
    b.write_text("again maria@gmail.com\n")
    main([str(a), str(b), "-q"])
    out = capsys.readouterr().out
    assert f"===== {a} =====\n<EMAIL_1>" in out and "again <EMAIL_1>" in out


def test_keep_term_domain_and_aggressive(tmp_path, capsys):
    f = tmp_path / "x.log"
    f.write_text("Acme GmbH at db.acme.internal 84.163.22.17 sig=Zq8Lm2Np4Rt6Vx9Bc1Df3Gh5Jk7Mn0Pq2Rs4\n")
    main([str(f), "--keep", "ipv4", "--term", "Acme GmbH", "--domain", "acme.internal", "--aggressive", "-q"])
    assert capsys.readouterr().out == "<TERM_1> at <HOST_1> 84.163.22.17 sig=<SECRET_1>\n"


def test_suspicious_strings_are_reported(tmp_path, capsys):
    f = tmp_path / "x.log"
    f.write_text("sig=Zq8Lm2Np4Rt6Vx9Bc1Df3Gh5Jk7Mn0Pq2Rs4\n")
    main([str(f)])
    assert "random-looking string Zq8L… was left in" in capsys.readouterr().err


def test_check_exits_one_and_masks(log, capsys):
    assert main(["check", str(log)]) == 1
    out, err = capsys.readouterr()
    assert f"{log}:1: pii email m…@…" in out and f"{log}:2: secret github_token ghp_…" in out
    assert h.GITHUB not in out and "3 sensitive values found" in err


def test_check_clean_file(tmp_path, capsys):
    f = tmp_path / "ok.txt"
    f.write_text("all good on 127.0.0.1\n")
    assert main(["check", str(f)]) == 0


def test_kinds_lists_every_category(capsys):
    assert main(["kinds"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("secret:") and "pii:" in out and "infra:" in out and "github_token" in out


def test_errors_exit_two(tmp_path, capsys):
    assert main([str(tmp_path / "missing.log")]) == 2
    assert main(["--keep", "nonsense", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "No such file" in err and "unknown kind or category in --keep: nonsense" in err


def test_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "share-safe 0.1.0" in capsys.readouterr().out
