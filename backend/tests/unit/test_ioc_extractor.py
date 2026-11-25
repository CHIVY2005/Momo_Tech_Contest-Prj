from app.services.ioc_extractor import extract_iocs, hash_ioc, mask_ioc


def test_extracts_vn_entities_without_confusing_currency_for_bank_account() -> None:
    text = (
        "Chuyển 2.500.000đ hoặc 15,000,000 VND vào STK 190384756201 tại Techcombank, "
        "liên hệ +84 912.345.678 hoặc truy cập https://vneid-dichvucong.vip/apk!"
    )
    iocs = extract_iocs(text)
    assert "0912345678" in iocs.phones
    assert "190384756201" in iocs.bank_accounts
    assert "2500000" not in iocs.bank_accounts
    assert "15000000" not in iocs.bank_accounts
    assert "https://vneid-dichvucong.vip/apk" in iocs.urls
    assert "vneid-dichvucong.vip" in iocs.domains
    assert "Techcombank" in iocs.brands
    assert "VNeID" in iocs.brands


def test_mask_and_hash_ioc_protect_pii() -> None:
    assert mask_ioc("phone", "0912345678") == "091****678"
    assert mask_ioc("bank_account", "190384756201") == "1903****6201"
    assert mask_ioc("domain", "sub.napas-diemthuong.top") == "sub.na****.top"
    h1 = hash_ioc("bank_account", "190384756201")
    h2 = hash_ioc("bank_account", " 190384756201 ")
    assert len(h1) == 64
    assert h1 == h2
