package app.washerctl

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Expected values come from web/candy_crypto.py (its self-test and direct runs). */
class CandyCryptoTest {
    private val wdKey = "ainackjmbnnnbjcd"
    private val dualKey = "lahncebdcbhnaebb"

    @Test fun xorKnownAnswers() {
        assertEquals("361B071506565B4B311A3D1A5F5A45341327035C525A", CandyCrypto.xorEncrypt("Write=1&StSt=0&PrNm=11", wdKey))
        assertEquals(
            "3B13011A0658534230163B1A5C554426090D250A5E554434112C055357",
            CandyCrypto.xorEncrypt("Write=1&StSt=0&DelMd=0&PrNm=6", dualKey),
        )
        assertEquals(
            "3B13011A065853423303555E4736070E51514E3E112B0F595A44381C220A060751565F",
            CandyCrypto.xorEncrypt("Write=1&Pa=0&Sel=0&PrNm=9&PrCode=77", dualKey),
        )
        assertEquals("Write=1&StSt=0&PrNm=11", CandyCrypto.xorDecrypt("361B071506565B4B311A3D1A5F5A45341327035C525A\n", wdKey))
        assertEquals("Write=1&StSt=0&PrNm=11", CandyCrypto.xorDecrypt("361b071506565b4b311a3d1a5f5a45341327035c525a", wdKey))
    }

    @Test fun wifibleCommands() {
        assertEquals(
            "Write=1&StSt=1&DelVl=0&PrNm=11&PrCode=2&PrStr=Eco Cottons&TmpTgt=40&SLevTgt=3&SpdTgt=14" +
                "&OptMsk1=0&OptMsk2=0&Lang=1&Stm=0&Dry=3&ED=0&RecipeId=0&StartCheckUp=0&DispTestOn=1",
            CandyCrypto.wifibleStart(prnm = 11, prcode = 2, prstr = "Eco Cottons", temp = 40, soil = 3, spinRpm = 1400, dry = 3),
        )
        assertEquals(
            "Write=1&StSt=1&DelVl=2&PrNm=3&PrCode=2&PrStr=Eco 40-60&SLevTgt=0&OptMsk1=0&OptMsk2=1" +
                "&Lang=1&Stm=0&Dry=0&ED=0&RecipeId=0&StartCheckUp=0&DispTestOn=1",
            CandyCrypto.wifibleStart(prnm = 3, prcode = 2, prstr = "Eco 40-60", soil = 255, spinRpm = 255, optmsk2 = 1, delaySteps = 2),
        )
        assertEquals("encrypted=0&Pa=1", CandyCrypto.wifiblePause())
        assertEquals("encrypted=0&Pa=0", CandyCrypto.wifibleResume())
        assertEquals("Write=1&StSt=0&PrNm=11", CandyCrypto.wifibleStop(11))
        assertEquals("Write=1&StSt=0&PrNm=11&DelVl=0", CandyCrypto.wifibleStop(11, delayed = true))
    }

    @Test fun dualCommands() {
        assertEquals(
            "Write=1&Pa=0&Sel=0&PrNm=12&PrCode=71&StSt=1&TmpTgt=20&TmpDf=40&SpdTgt=10&SpdDef=14" +
                "&Stm=0&Dry=0&Option=0&RecipeId=0&CheckUpState=0",
            CandyCrypto.dualStart(prnm = 12, defaultTemp = 40, defaultSpinRpm = 1400, defaultSoil = 9,
                temp = 20, spinRpm = 1000, soil = 9, dry = 0, prcode = 71),
        )
        assertEquals(
            "Write=1&Pa=0&Sel=0&PrNm=9&PrCode=77&DelMd=1&DelVl=3&Stm=0&Dry=8&Option=8&RecipeId=0&CheckUpState=0",
            CandyCrypto.dualStart(prnm = 9, defaultTemp = 255, defaultSpinRpm = 255, defaultSoil = 0,
                temp = 255, spinRpm = 255, soil = 0, dry = 8, delaySteps = 3, dryOnly = true, prcode = 77),
        )
        assertEquals(
            "Write=1&Pa=0&Sel=0&PrNm=2&PrCode=65&StSt=1&TmpTgt=90&TmpDf=60&SLevTgt=2&OptMsk=17" +
                "&Stm=5&Dry=3&Option=3&RecipeId=0&CheckUpState=0",
            CandyCrypto.dualStart(prnm = 2, defaultTemp = 60, defaultSpinRpm = 1400, defaultSoil = 3,
                temp = 90, spinRpm = 1400, soil = 1, optmsk = 17, steam = 5, dry = 3, prcode = 65),
        )
        assertEquals("Write=1&StSt=0&DelMd=0&PrNm=6", CandyCrypto.dualStop(6))
    }

    @Test fun decodeStatusMatchesPython() {
        val st = """{"statusLavatrice":{"WiFiStatus":"1","Err":"255","MachMd":"2","PrNm":"9","PrPh":"6","SLevel":"0",""" +
            """"Temp":"0","SpinSp":"0","Opt1":"0","Opt3":"1","RemTime":"1800","DelVal":"0","Steam":"0","DryT":"8","RecipeId":"0"}}"""
        val out = CandyCrypto.decodeStatus(CandyCrypto.xorEncrypt(st, dualKey), dualKey)
        val expected = JSONObject(
            """{"machine_mode": [2, "running"], "phase": [6, "drying"], "program_number": 9, "program_code": null,
            "temperature_C": 0, "spin_rpm": 0, "soil_level": 0, "remaining_time_s": 1800, "delay_value": 0,
            "remote_control_enabled": true, "error_code": "255", "options_mask1": 4, "options": ["anti-crease"],
            "steam": 0, "dry_type": 8, "recipe_id": "0"}"""
        )
        for (k in expected.keys()) assertEquals(k, expected.get(k).toString(), out.get(k).toString())
        assertEquals("9", out.getJSONObject("raw").getString("PrNm"))
    }

    @Test fun macFromUdpPacket() {
        val pkt = ByteArray(120)
        "x0200deadbeefrest".toByteArray().copyInto(pkt, 60)
        assertEquals("0200deadbeef", Net.macFromPacket(pkt))
        assertNull(Net.macFromPacket(ByteArray(50)))
    }
}
