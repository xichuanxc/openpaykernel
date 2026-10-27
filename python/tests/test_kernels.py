from openpaykernel import (AmexKernel, AutoHost, ContactKernel, DiscoverKernel, EntryPoint, JcbKernel, MastercardKernel, OnlineResponse,
                           TerminalConfig, UnionPayKernel, VisaKernel)
from openpaykernel.config import bit
from openpaykernel.outcome import CVM, L2Error, Status
from openpaykernel.sim.card import CardProfile, SimCard, VISA_AID

import scenarios as sc


def ep(*aids):
    return EntryPoint(sc.env(list(aids)), [VisaKernel(), MastercardKernel(), UnionPayKernel(), DiscoverKernel(),
                                                AmexKernel(), JcbKernel()])


# ---------------------------------------------------------------------------- Visa
def test_visa_offline_approved_with_fdda():
    card = sc.visa_card()
    out = ep(sc.visa_aid_cfg()).process(card, sc.txn(1000))
    assert out.status == Status.APPROVED, out
    assert out.cvm == CVM.NO_CVM
    assert out.data_record[0x9F27] == b"\x40"


def test_visa_fdda_failure_goes_online_when_ctq_allows():
    card = sc.visa_card(corrupt_sdad=True, ctq=bytes.fromhex("2000"))  # CTQ: go online if ODA fails
    out = ep(sc.visa_aid_cfg()).process(card, sc.txn(1000))
    assert out.status == Status.ONLINE_REQUEST


def test_visa_fdda_failure_declines_otherwise():
    card = sc.visa_card(corrupt_sdad=True, ctq=bytes.fromhex("0000"))
    out = ep(sc.visa_aid_cfg()).process(card, sc.txn(1000))
    assert out.status == Status.DECLINED


def test_visa_cvm_required_online_pin():
    card = sc.visa_card(ctq=bytes.fromhex("8000"), decision="online")
    out = ep(sc.visa_aid_cfg()).process(card, sc.txn(4000))  # TTQ 36: online PIN supported
    assert out.status == Status.ONLINE_REQUEST
    assert out.cvm == CVM.ONLINE_PIN
    ttq = out.data_record[0x9F66]
    assert bit(ttq, 2, 7)  # CVM required set by pre-processing


def test_visa_signature_when_cvm_required():
    card = sc.visa_card(ctq=bytes.fromhex("4000"), decision="online")
    out = ep(sc.visa_aid_cfg()).process(card, sc.txn(4000))
    assert out.status == Status.ONLINE_REQUEST
    assert out.cvm == CVM.SIGNATURE and out.receipt


def test_visa_over_contactless_limit_tries_another_interface():
    out = ep(sc.visa_aid_cfg()).process(sc.visa_card(), sc.txn(60000))
    assert out.status == Status.TRY_ANOTHER_INTERFACE


def test_visa_see_phone():
    out = ep(sc.visa_aid_cfg()).process(sc.visa_card(gpo_sw=0x6986), sc.txn(100))
    assert out.status == Status.TRY_AGAIN
    assert out.ui_request.message.name == "SEE_PHONE"


def test_visa_expired_card_offline_declined_by_ctq_rules():
    card = sc.visa_card(expiry=bytes.fromhex("200101"), ctq=bytes.fromhex("0000"))
    out = ep(sc.visa_aid_cfg()).process(card, sc.txn(1000))
    assert out.status == Status.DECLINED


def test_ppse_no_matching_aid():
    out = ep(sc.mc_aid_cfg()).process(sc.visa_card(), sc.txn(100))
    assert out.status == Status.END_APPLICATION
    assert out.error.l2 == L2Error.EMPTY_CANDIDATE_LIST


# ---------------------------------------------------------------------------- Mastercard
def test_mc_cda_offline_approved():
    card = sc.mc_card()
    out = ep(sc.mc_aid_cfg()).process(card, sc.txn(1000))
    assert out.status == Status.APPROVED, out
    assert out.data_record[0x95] == bytes(5)
    gac = [c for c, _ in card.log if c[1] == 0xAE][0]
    assert gac[2] == 0x50  # TC + CDA


def test_mc_cda_failure_declines():
    card = sc.mc_card(corrupt_sdad=True)
    out = ep(sc.mc_aid_cfg()).process(card, sc.txn(1000))
    assert out.status == Status.DECLINED
    assert out.error.l2 == L2Error.CAM_FAILED
    assert bit(out.data_record[0x95], 1, 3)


def test_mc_above_floor_goes_online_with_online_pin():
    card = sc.mc_card()
    out = ep(sc.mc_aid_cfg()).process(card, sc.txn(15000))
    assert out.status == Status.ONLINE_REQUEST
    assert out.cvm == CVM.ONLINE_PIN
    assert out.data_record[0x9F34] == bytes.fromhex("420300")


def test_mc_signature_when_reader_has_no_pin_pad():
    cfg = sc.mc_aid_cfg()
    cfg.extra[0xDF8118] = b"\x20"
    out = ep(cfg).process(sc.mc_card(), sc.txn(15000))
    assert out.cvm == CVM.SIGNATURE and out.receipt
    assert out.data_record[0x9F34] == bytes.fromhex("1E0300")
    assert bit(out.data_record[0x95], 4, 8)


def test_mc_on_device_cvm():
    card = sc.mc_card(aip=bytes.fromhex("1B80"))
    out = ep(sc.mc_aid_cfg()).process(card, sc.txn(40000))  # above 300 no-CDCVM limit but under 500
    assert out.cvm == CVM.CONFIRMATION_CODE_VERIFIED
    assert out.data_record[0x9F34] == bytes.fromhex("010002")
    assert out.status == Status.ONLINE_REQUEST


def test_mc_over_limit_select_next():
    out = ep(sc.mc_aid_cfg()).process(sc.mc_card(), sc.txn(40000))
    assert out.status == Status.END_APPLICATION  # SELECT NEXT exhausted the candidate list


def test_mc_without_cda_sets_oda_not_performed():
    card = sc.mc_card(aip=bytes.fromhex("1880"), oda="none")
    out = ep(sc.mc_aid_cfg()).process(card, sc.txn(1000))
    assert bit(out.data_record[0x95], 1, 8)
    assert out.status == Status.ONLINE_REQUEST  # TAC online includes ODA not performed


# ---------------------------------------------------------------------------- Contact
def contact(card, host=None, terminal=None, amount=2000, **kw):
    k = ContactKernel(sc.env(sc.contact_aid_cfgs(), terminal), host or AutoHost())
    return k.process(card, sc.txn(amount, **kw))


def test_contact_dda_offline_pin_offline_approved():
    host = AutoHost()
    card = sc.contact_card(cvm_list=bytes.fromhex("000000000000000041031E031F03"))
    res = contact(card, host)
    assert res.outcome.status == Status.APPROVED, res.outcome
    assert res.outcome.cvm == CVM.OFFLINE_PIN
    assert res.data[0x9F34] == bytes.fromhex("410302")
    assert res.data[0x95] == bytes(5)
    assert bit(res.data[0x9B], 1, 8) and bit(res.data[0x9B], 1, 7)
    assert host.pin_requests == [(False, 3)]


def test_contact_wrong_pin_then_right():
    calls = iter(["0000", "1234"])

    class H(AutoHost):
        def enter_pin(self, online, tries):
            self.pin_requests.append((online, tries))
            return next(calls)

    host = H()
    res = contact(sc.contact_card(cvm_list=bytes.fromhex("000000000000000001031F03")), host)
    assert res.outcome.status == Status.APPROVED
    assert host.pin_requests == [(False, 3), (False, 2)]


def test_contact_enciphered_offline_pin():
    res = contact(sc.contact_card(cvm_list=bytes.fromhex("000000000000000044031F03")))
    assert res.outcome.cvm == CVM.OFFLINE_PIN
    assert res.data[0x9F34] == bytes.fromhex("440302")


def test_contact_online_approved_with_scripts_and_issuer_auth():
    scripts = bytes.fromhex("710F9F180400000001860684240000000A") \
        + bytes.fromhex("720F9F180400000002860684DA9F580101")
    host = AutoHost(online=OnlineResponse(True, b"00", bytes.fromhex("1122334455667788" "3030"), scripts))
    card = sc.contact_card(aip=bytes.fromhex("3C04"), cvm_list=bytes.fromhex("000000000000000042031F03"))
    res = contact(card, host, amount=20000)  # above floor limit → online
    assert res.outcome.status == Status.APPROVED
    assert res.outcome.cvm == CVM.ONLINE_PIN
    assert host.online_requests and 0x9F26 in host.online_requests[0]
    assert card.current is not None and len(card.script_commands) == 2
    assert card.external_auth == [bytes.fromhex("11223344556677883030")]
    assert res.script_results == bytes.fromhex("2000000001" "2000000002")
    assert bit(res.data[0x9B], 1, 5) and bit(res.data[0x9B], 1, 3)


def test_contact_online_declined():
    host = AutoHost(online=OnlineResponse(False, b"05"))
    res = contact(sc.contact_card(), host, amount=20000)
    assert res.outcome.status == Status.DECLINED
    assert res.data[0x8A] == b"05"


def test_contact_unable_to_go_online_uses_default_action():
    class Offline(AutoHost):
        def go_online(self, data):
            return None

    res = contact(sc.contact_card(), Offline(), amount=20000)
    # TAC default includes 'floor limit exceeded' → AAC
    assert res.outcome.status == Status.DECLINED
    assert res.data[0x8A] == b"Z3"


def test_contact_sda():
    res = contact(sc.contact_card(aip=bytes.fromhex("5C00"), oda="sda"))
    assert res.data[0x9F45] == b"\xDA\xC1"
    assert bit(res.data[0x95], 1, 2) and not bit(res.data[0x95], 1, 7)


def test_contact_cda_two_generate_ac():
    card = sc.contact_card(aip=bytes.fromhex("3D00"), oda="cda", cvm_list=bytes.fromhex("000000000000000042031F03"))
    host = AutoHost(online=OnlineResponse(True, b"00"))
    term = TerminalConfig(capabilities=bytes.fromhex("E0F8E8"))  # + CDA
    res = contact(card, host, terminal=term, amount=20000)
    assert res.outcome.status == Status.APPROVED, res.data.get(0x95)
    gacs = [c for c, _ in card.log if c[1] == 0xAE]
    assert [g[2] for g in gacs] == [0x90, 0x50]
    assert not bit(res.data[0x95], 1, 3)


def test_contact_cda_failure():
    card = sc.contact_card(aip=bytes.fromhex("3D00"), oda="cda", corrupt_sdad=True)
    term = TerminalConfig(capabilities=bytes.fromhex("E0F8E8"))
    res = contact(card, AutoHost(), terminal=term, amount=20000)
    assert res.outcome.status == Status.DECLINED
    assert bit(res.data[0x95], 1, 3)


def test_contact_expired_and_velocity():
    card = sc.contact_card(expiry=bytes.fromhex("250101"), lcol=1, ucol=2)
    res = contact(card, AutoHost(), amount=100)
    tvr = res.data[0x95]
    assert bit(tvr, 2, 7)          # expired
    assert bit(tvr, 4, 7) and bit(tvr, 4, 6)  # ATC 0x11 - last online 0x0C = 5 > limits


def test_contact_multi_application_priority():
    mc = CardProfile(aid=bytes.fromhex("A0000000041010"), priority=2, label=b"MC")
    visa = CardProfile(aid=VISA_AID, priority=1, label=b"VISA")
    chosen = []

    class H(AutoHost):
        def choose_application(self, cands):
            chosen.append([c.label for c in cands])
            return 1

    res = contact(SimCard(mc, visa), H())
    assert chosen == [["VISA", "MC"]]
    assert res.data[0x84] == bytes.fromhex("A0000000041010")


def test_contact_list_of_aids_when_no_pse():
    card = SimCard(CardProfile(aid=VISA_AID, in_pse=False))
    res = contact(card)
    assert res.outcome.status in (Status.APPROVED, Status.DECLINED)
    assert any(c[5:5 + c[4]] == VISA_AID[:7] for c, _ in card.log if c[1] == 0xA4)


def test_card_cannot_overwrite_terminal_data():
    # A card that injects Terminal Capabilities / TTQ / TVR in its FCI must not change them
    from openpaykernel.tlv import encode
    evil = encode(0x9F33, b"\x00\x00\x00") + encode(0x95, b"\x00" * 5) + encode(0x9F35, b"\x11")
    res = contact(sc.contact_card(extra_fci=evil, cvm_list=bytes.fromhex("000000000000000041031F03")))
    assert res.data[0x9F33] == bytes.fromhex("E0F8C8")
    assert res.data[0x9F35] == b"\x22"
    out = ep(sc.visa_aid_cfg()).process(sc.visa_card(extra_fci=encode(0x9F66, b"\xFF" * 4)), sc.txn(1000))
    assert out.data_record[0x9F66] == bytes.fromhex("36004000")


def test_malformed_pin_from_host_is_a_failed_cvm():
    # rule 01 03 without "apply next": a failed PIN ends CVM processing as failed
    res = contact(sc.contact_card(cvm_list=bytes.fromhex("000000000000000001031F03")), AutoHost(pin="12"))
    assert res.data[0x9F34] == bytes.fromhex("010301")
    assert bit(res.data[0x95], 3, 8)  # cardholder verification was not successful
    # rule 41 03 ("apply next"): falls through to No CVM required
    res = contact(sc.contact_card(cvm_list=bytes.fromhex("000000000000000041031F03")), AutoHost(pin="12"))
    assert res.data[0x9F34] == bytes.fromhex("1F0302")


# ---------------------------------------------------------------------------- UnionPay (kernel 7)
def test_upi_offline_approved_with_fdda_and_offline_balance():
    out = ep(sc.upi_aid_cfg()).process(sc.upi_card(), sc.txn(1000))
    assert out.status == Status.APPROVED, out
    assert out.data_record[0x9F5D] == bytes.fromhex("000000050000")
    assert bit(out.data_record[0x9F66], 1, 6)  # qUICS/qVSDC supported in TTQ


def test_upi_cvm_required_signature_online():
    out = ep(sc.upi_aid_cfg()).process(sc.upi_card(ctq=bytes.fromhex("4000"), decision="online"), sc.txn(4000))
    assert out.status == Status.ONLINE_REQUEST and out.cvm == CVM.SIGNATURE


def test_upi_fdda_failure_declines():
    out = ep(sc.upi_aid_cfg()).process(sc.upi_card(corrupt_sdad=True, ctq=bytes.fromhex("0000")), sc.txn(1000))
    assert out.status == Status.DECLINED


def test_upi_selected_by_rid_default_kernel_id():
    # AID config without an explicit kernel ID resolves to kernel 7 from the UnionPay RID
    out = ep(sc.upi_aid_cfg(kernel_id=0)).process(sc.upi_card(), sc.txn(1000))
    assert out.status == Status.APPROVED


# ---------------------------------------------------------------------------- Discover (kernel 6)
def test_discover_cda_offline_approved():
    card = sc.discover_card()
    out = ep(sc.discover_aid_cfg()).process(card, sc.txn(1000))
    assert out.status == Status.APPROVED, out
    assert out.cvm == CVM.NO_CVM and out.data_record[0x9F34] == bytes.fromhex("3F0000")
    gac = [c for c, _ in card.log if c[1] == 0xAE][0]
    assert gac[2] == 0x50  # TC + CDA
    assert out.data_record[0x9F71] == bytes.fromhex("4000")


def test_discover_cvm_required_signature_from_cpr():
    out = ep(sc.discover_aid_cfg()).process(sc.discover_card(), sc.txn(4000))
    assert out.status == Status.APPROVED and out.cvm == CVM.SIGNATURE and out.receipt
    assert out.data_record[0x9F34] == bytes.fromhex("1E0300")


def test_discover_online_pin_forces_online():
    out = ep(sc.discover_aid_cfg()).process(sc.discover_card(ctq=bytes.fromhex("8000")), sc.txn(4000))
    assert out.status == Status.ONLINE_REQUEST and out.cvm == CVM.ONLINE_PIN


def test_discover_cda_failure_declines():
    out = ep(sc.discover_aid_cfg()).process(sc.discover_card(corrupt_sdad=True), sc.txn(1000))
    assert out.status == Status.DECLINED and out.error.l2.name == "CAM_FAILED"


def test_discover_cash_switches_interface_when_cpr_asks():
    out = ep(sc.discover_aid_cfg()).process(sc.discover_card(ctq=bytes.fromhex("0400")), sc.txn(1000, type=0x01))
    assert out.status == Status.TRY_ANOTHER_INTERFACE


def test_discover_no_cvm_possible_declines():
    out = ep(sc.discover_aid_cfg()).process(sc.discover_card(ctq=bytes.fromhex("0000")), sc.txn(4000))
    assert out.status == Status.DECLINED and out.data_record[0x9F34] == bytes.fromhex("3F0001")


def test_generate_ac_error_status_word_reports_status_bytes():
    for card, cfg in ((sc.mc_card(gac_sw=0x6985), sc.mc_aid_cfg()), (sc.discover_card(gac_sw=0x6985), sc.discover_aid_cfg())):
        out = ep(cfg).process(card, sc.txn(1000))
        assert out.status == Status.END_APPLICATION
        assert out.error.l2 == L2Error.STATUS_BYTES and out.error.sw12 == 0x6985


# ---------------------------------------------------------------------------- American Express (kernel 4)
def test_amex_cda_offline_approved_and_reader_capabilities_sent():
    card = sc.amex_card()
    out = ep(sc.amex_aid_cfg()).process(card, sc.txn(1000))
    assert out.status == Status.APPROVED, out
    gpo = [c for c, _ in card.log if c[1] == 0xA8][0]
    assert bytes.fromhex("D8E00003") in gpo  # 9F6E sent in the PDOL data, CVM-required bit clear
    assert out.cvm == CVM.NO_CVM and out.data_record[0x9F34] == bytes.fromhex("1F0302")


def test_amex_cvm_required_sets_9f6e_and_uses_online_pin():
    card = sc.amex_card()
    out = ep(sc.amex_aid_cfg()).process(card, sc.txn(4000))
    gpo = [c for c, _ in card.log if c[1] == 0xA8][0]
    assert bytes.fromhex("D8E04003") in gpo  # byte 3 bit 7: CVM required
    assert out.cvm == CVM.ONLINE_PIN and out.status == Status.ONLINE_REQUEST


def test_amex_signature_when_reader_has_no_pin():
    cfg = sc.amex_aid_cfg(extra={0x9F6E: bytes.fromhex("D8A00003")})  # mobile CVM + signature, no online PIN
    out = ep(cfg).process(sc.amex_card(), sc.txn(4000))
    assert out.cvm == CVM.SIGNATURE and out.receipt


def test_amex_mobile_cvm():
    card = sc.amex_card(extra_gpo=bytes.fromhex("9F7103010002"))
    out = ep(sc.amex_aid_cfg()).process(card, sc.txn(4000))
    assert out.cvm == CVM.CONFIRMATION_CODE_VERIFIED
    assert out.data_record[0x9F34] == bytes.fromhex("010002")


def test_amex_cda_failure_declines():
    out = ep(sc.amex_aid_cfg()).process(sc.amex_card(corrupt_sdad=True), sc.txn(1000))
    assert out.status == Status.DECLINED and out.error.l2 == L2Error.CAM_FAILED


def test_amex_magstripe_only_card_is_not_supported():
    out = ep(sc.amex_aid_cfg()).process(sc.amex_card(aip=bytes.fromhex("1900")), sc.txn(1000))
    assert out.status == Status.END_APPLICATION and out.error.l2 == L2Error.MAGSTRIPE_NOT_SUPPORTED


# ---------------------------------------------------------------------------- JCB (kernel 5)
def test_jcb_cda_offline_approved_with_tip():
    card = sc.jcb_card()
    out = ep(sc.jcb_aid_cfg()).process(card, sc.txn(1000))
    assert out.status == Status.APPROVED, out
    gpo = [c for c, _ in card.log if c[1] == 0xA8][0]
    assert bytes.fromhex("720000") in gpo  # TIP, CVM-required bit clear
    assert out.data_record[0x9F34] == bytes.fromhex("1F0302")


def test_jcb_cvm_required_online_pin_from_tip():
    card = sc.jcb_card()
    out = ep(sc.jcb_aid_cfg()).process(card, sc.txn(4000))
    gpo = [c for c, _ in card.log if c[1] == 0xA8][0]
    assert bytes.fromhex("F20000") in gpo  # byte 1 bit 8: CVM required
    assert out.cvm == CVM.ONLINE_PIN and out.status == Status.ONLINE_REQUEST


def test_jcb_on_device_cvm():
    out = ep(sc.jcb_aid_cfg()).process(sc.jcb_card(aip=bytes.fromhex("1B80")), sc.txn(4000))
    assert out.cvm == CVM.CONFIRMATION_CODE_VERIFIED and out.data_record[0x9F34] == bytes.fromhex("010002")


def test_jcb_signature_only_reader():
    out = ep(sc.jcb_aid_cfg(extra={0x9F53: bytes.fromhex("420000")})).process(sc.jcb_card(), sc.txn(4000))
    assert out.cvm == CVM.SIGNATURE and out.receipt


def test_jcb_cda_failure_declines():
    out = ep(sc.jcb_aid_cfg()).process(sc.jcb_card(corrupt_sdad=True), sc.txn(1000))
    assert out.status == Status.DECLINED and out.error.l2 == L2Error.CAM_FAILED


def test_all_six_kernels_from_one_ppse_configuration():
    # One terminal configuration with every brand; each card is routed to its own kernel
    aids = [sc.visa_aid_cfg(), sc.mc_aid_cfg(), sc.upi_aid_cfg(), sc.discover_aid_cfg(), sc.amex_aid_cfg(),
            sc.jcb_aid_cfg()]
    for card in (sc.visa_card(), sc.mc_card(), sc.upi_card(), sc.discover_card(), sc.amex_card(), sc.jcb_card()):
        assert ep(*aids).process(card, sc.txn(1000)).status == Status.APPROVED
