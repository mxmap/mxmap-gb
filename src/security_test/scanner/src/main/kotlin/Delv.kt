import Dig.createTmpPath

import models.dataClass.DigCmdResult
import java.io.File
import Config

object Delv {

    private fun delvCmd(domain: String, type: String = "A", resolver: String = Config["DNS_NAMESERVER"]): String {

        val logfilepath = createTmpPath()


        val pb = ProcessBuilder("timeout", "30", "delv", "+cdflag" ,"@" + resolver, domain, type)


        val logfile = File(logfilepath)
        pb.redirectOutput(ProcessBuilder.Redirect.appendTo(logfile))
        pb.redirectError(ProcessBuilder.Redirect.appendTo(logfile))
        val exitcode = pb.start().waitFor()

        val log = File(logfilepath).readText(Charsets.UTF_8)
        logfile.delete()

        return log
    }


    public fun delv(domian: String, type: String = "A", resolver: String = Config["DNS_NAMESERVER"]):String  {

        return delvCmd(domian, type, resolver)

    }




}