from app.services.ioc_extractor import extract_iocs, hash_ioc, mask_ioc


def test_extracts_vn_entities_and_preserves_phone_shaped_bank_accounts() -> None:
    text = (
        "Chuyển 2.500.000đ hoặc 15,000,000 VND vào STK: 0987654321 tại MB Bank "
        "hoặc TK 190384756201 Techcombank, liên hệ +84 912.345.678 "
        "hoặc truy cập https://vneid-dichvucong.vip/apk!"
    )
    iocs = extract_iocs(text)
    # Explicitly labeled STK: 0987654321 must be preserved as a bank_account!
    assert "0987654321" in iocs.bank_accounts
    assert "190384756201" in iocs.bank_accounts
    assert "0912345678" in iocs.phones
    assert "0987654321" not in iocs.phones
    assert "2500000" not in iocs.bank_accounts
    assert "15000000" not in iocs.bank_accounts
    assert "https://vneid-dichvucong.vip/apk" in iocs.urls
    assert "vneid-dichvucong.vip" in iocs.domains
    assert "Techcombank" in iocs.brands
    assert "MB Bank" in iocs.brands
    assert "VNeID" in iocs.brands


def test_mask_and_hash_ioc_protect_pii() -> None:
    assert mask_ioc("phone", "0912345678") == "091****678"
    assert mask_ioc("bank_account", "190384756201") == "19****01"
    assert mask_ioc("domain", "sub.napas-diemthuong.top") == "*.na****.top"
    assert mask_ioc("domain", "0912345678.napas-diemthuong.top") == "*.na****.top"
    h1 = hash_ioc("bank_account", "190384756201")
    h2 = hash_ioc("bank_account", " 190384756201 ")
    assert len(h1) == 64
    assert h1 == h2
