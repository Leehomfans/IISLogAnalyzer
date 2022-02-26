using IISLogParser;
using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Configuration;
namespace ConsoleApp3
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            string filepath = ConfigurationManager.AppSettings["logfilepath"].ToString();
            IISlogAnalyzer(filepath, @".php$");
            sw.Stop();
            Console.WriteLine($"用时:{sw.ElapsedMilliseconds}ms");
            Console.Read();
        }
        /// <summary>
        /// IIS日志分析器
        /// </summary>
        /// <param name="filepath"></param>
        public  static void IISlogAnalyzer(string filepath,string regexExpression)
        {
            List<IISLogEvent> logs = new List<IISLogEvent>();
            Regex regex = new Regex(regexExpression);
            using (ParserEngine parser = new ParserEngine(filepath))
            {
                while (parser.MissingRecords)
                {
                    logs = parser.ParseLog().ToList();
                }
                List<string> ipList= logs.Where(item =>!string.IsNullOrEmpty(item.csUriStem)&&regex.IsMatch(item.csUriStem)).Select(i => i.cIp).Distinct().ToList();
                string ips=string.Join(",", ipList);
                PutFireWall(ips);
            }
        }
        /// <summary>
        /// 加入防火墙黑名单
        /// </summary>
        /// <param name="ip"></param>
        public static void PutFireWall(string ip)
        {
            INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            var rule = firewallPolicy.Rules.Item("Block Bad IP Addresses");
            rule.RemoteAddresses += "," + ip;
        }
        void regex_match()
        {
            Regex re = new Regex("<a.*href='/(.*)\'", RegexOptions.Multiline);
            string html = "<li><link href='/asjdjsa.html'><a id='mnuPhotoList' href='http:121/companyphotos.htm'>公司相册</a><a id='mnuPhotoList' href='/companyphotos.htm'>公司相册</a></li>";
            var a = re.Matches(html);
            StringBuilder str = new StringBuilder();
            foreach (Match b in a)
            {
                if (b.Success)
                {
                    str.Append(b.Groups[1].Value);
                }
            }
            string newhtml = re.Replace(html, m =>
            {
                if (m.Success && !m.Groups[1].Value.Contains("http"))
                {
                    return m.Value.Replace(m.Groups[1].Value, "http:zhou123321.51sole.com/" + m.Groups[1].Value);
                }
                else
                {
                    return m.Value;
                }

            });
        }
    }
}
