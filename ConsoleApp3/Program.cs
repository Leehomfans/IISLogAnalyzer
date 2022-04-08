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
using System.Linq.Expressions;
using System.IO;

namespace ConsoleApp3
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            Expression<Func<IISLogEvent, bool>> expression = item=> 1!=1;
            string filepath = ConfigurationManager.AppSettings["IISlogDir"].ToString();
            if(!Directory.Exists(filepath))
            {
                Console.WriteLine("目录不存在");
            }
            else
            {
                var lastfilepath = (from f in Directory.GetFiles(filepath)
                             let fi = new FileInfo(f)
                             orderby fi.CreationTime descending
                             select fi.FullName).FirstOrDefault();
                if(string.IsNullOrEmpty(lastfilepath))
                {
                    Console.WriteLine("文件夹下面没有文件");
                }
                filepath = lastfilepath;
            }
            string requestPathRegex= ConfigurationManager.AppSettings["PathRegex"].ToString();
            string UARegex = ConfigurationManager.AppSettings["UARegex"].ToString();
            if(!string.IsNullOrEmpty(requestPathRegex))
            {
                Regex regex = new Regex(requestPathRegex);
                expression = expression.ExpressionOr(item => regex.IsMatch(item.csUriStem));
            }
            if(!string.IsNullOrEmpty(UARegex))
            {
                Regex regex = new Regex(UARegex);
                expression = expression.ExpressionOr(item => regex.IsMatch(item.csUserAgent));
            }
            IISlogAnalyzer(filepath, expression.Compile());
            sw.Stop();
            Console.WriteLine($"用时:{sw.ElapsedMilliseconds}ms");
            Console.Read();
        }
        /// <summary>
        /// IIS日志分析器
        /// </summary>
        /// <param name="filepath"></param>
        public static void IISlogAnalyzer(string filepath, Func<IISLogEvent, bool> express,int cnt=1000)
        {
            List<IISLogEvent> logs = new List<IISLogEvent>();
            using (ParserEngine parser = new ParserEngine(filepath))
            {
                while (parser.MissingRecords)
                {
                    logs = parser.ParseLog().ToList();
                }
                string hostIp = logs.Select(g => g.sIp).FirstOrDefault();
                string expireTS = ConfigurationManager.AppSettings["expirets"].ToString();
                ResetFireWallBlackIp("Block Bad IP Addresses", hostIp, expireTS);//清除防火墙中过期的黑名单Ip
                List<string> ipList = new List<string>();
                ipList=logs.Where(express).Select(i => i.cIp).Distinct().ToList();
                ipList=ipList.Union(logs.GroupBy(item => item.cIp).Select(g => new { cip = g.Key, cnt = g.Count() }).Where(g => g.cnt > cnt).Select(i => i.cip).ToList()).ToList();
                string ips=string.Join(",", ipList);
                Console.WriteLine("发现异常IP:"+ ips);
                PutFireWall(ips);
            }
        }
        /// <summary>
        /// 加入防火墙黑名单
        /// </summary>
        /// <param name="ip"></param>
        public static void PutFireWall(string ip)
        {
            if(!string.IsNullOrEmpty(ip))
            {
                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                var rule = firewallPolicy.Rules.Item("Block Bad IP Addresses");
                rule.RemoteAddresses += "," + ip;
            }
        }
        /// <summary>
        /// 放开超过指定时间的黑名单IP
        /// </summary>
        public static void ResetFireWallBlackIp(string ruleName, string hostip, string expireTS)
        {
            DateTime dt = DateTime.Parse(expireTS);
            TimeSpan ts = new TimeSpan(dt.Hour, dt.Minute, dt.Second);
            string specDate = DateTime.Now.Subtract(ts).ToString("yyyy-MM-dd HH:mm:ss");
            string sql = "select blackip from Filter_BlackIP where hostip='" + hostip + "' and  createtime<='" + specDate + "';";
            //DataSet ds = DB.DataSet(connstr, sql);
            //if (DataHelper.ExistsDataSet(ds))
            //{
            //    List<string> blackIpList = (from d in ds.Tables[0].AsEnumerable() select d.Field<string>("blackip") + "/255.255.255.255").ToList();

            //    sql = "delete from Filter_BlackIP where hostip='" + hostip + "' and  createtime<='" + specDate + "';";
            //    int res = DB.Query(connstr, sql);
            //    if (res > 0)
            //    {

                    
            //        LogHelper.WriteLog("info", "ResetFireWallBlackIp", "重置黑名单" + ips + "成功");
            //    }
            //    else
            //    {
            //        LogHelper.WriteLog("error", "ResetFireWallBlackIp", "重置黑名单IP失败!");
            //    }
            //}
        }

    }
}
public static class ExpressionHelp
{
    private static Expression<T> Combine<T>(this Expression<T> first, Expression<T> second, Func<Expression, Expression, Expression> merge)
    {
        MyExpressionVisitor visitor = new MyExpressionVisitor(first.Parameters[0]);
        Expression bodyone = visitor.Visit(first.Body);
        Expression bodytwo = visitor.Visit(second.Body);
        return Expression.Lambda<T>(merge(bodyone, bodytwo), first.Parameters[0]);
    }
    public static Expression<Func<T, bool>> ExpressionAnd<T>(this Expression<Func<T, bool>> first, Expression<Func<T, bool>> second)
    {
        return first.Combine(second, Expression.And);
    }
    public static Expression<Func<T, bool>> ExpressionOr<T>(this Expression<Func<T, bool>> first, Expression<Func<T, bool>> second)
    {
        return first.Combine(second, Expression.Or);
    }
}
public class MyExpressionVisitor : ExpressionVisitor
{
    public ParameterExpression _Parameter { get; set; }

    public MyExpressionVisitor(ParameterExpression Parameter)
    {
        _Parameter = Parameter;
    }
    protected override Expression VisitParameter(ParameterExpression p)
    {
        return _Parameter;
    }

    public override Expression Visit(Expression node)
    {
        return base.Visit(node);//Visit会根据VisitParameter()方法返回的Expression修改这里的node变量
    }
}
