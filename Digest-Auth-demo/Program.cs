using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Digest_Auth_demo
{

     static class Program
    {
        /*
         * 
HA1=MD5(A1)=MD5(username:realm:password)  
如果 qop 值为“auth”或未指定，那么 HA2 为  
HA2=MD5(A2)=MD5(method:digestURI)  
如果 qop 值为“auth-int”，那么 HA2 为  
HA2=MD5(A2)=MD5(method:digestURI:MD5(entityBody))  
如果 qop 值为“auth”或“auth-int”，那么如下计算 response：  
response=MD5(HA1:nonce:nonceCount:clientNonce:qop:HA2)  

         * */
        static void Main(string[] args)
        {
            /*
             * 
Authorization: Digest username="Mufasa",  
                     realm="testrealm@host.com",  
                     nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",  
                     uri="/dir/index.html",  
                     qop=auth,  
                     nc=00000001,  
                     cnonce="0a4f113b",  
                     response="6629fae49393a05397450978507c4ef1",  
                     opaque="5ccc069c403ebaf9f0171e9517f40e41"            
              */

            /*
            Digest username="18520477660", 
            realm ="120.27.83.99", 
            nonce="2a6acb35e224236b5c5eccd842345bb0", 
            uri="sip:sip.hori-gz.com", 
            response="7c7ca1d340b634d6cde250736490bcdf", 
            algorithm=MD5, 
            cnonce="Q3zMbCenS.wf4zGuMkx6TmhoXxfk.7pR0acP",
            qop=auth, nc=00000001
                */

            // lxj pass
            //string response = "7c7ca1d340b634d6cde250736490bcdf";
            //string realm = "120.27.83.99";
            //string method = "REGISTER";
            //string uri = "sip:sip.hori-gz.com";
            //string username = "18520477660";
            //string password = "888888";
            //string nonce = "2a6acb35e224236b5c5eccd842345bb0";
            //string nc = "00000001";
            //string cnonce = "Q3zMbCenS.wf4zGuMkx6TmhoXxfk.7pR0acP";
            //string qop = "auth";

            /*
             * 
             Authorization: Digest username="600013160907030@tt.hori-gz.com", realm="139.129.86.228", nonce="cfde464b7e367939cec45964e6e7dfce",
             uri="sip:tt.hori-gz.com", response="c6226201d879e80e20c698fb584e5d7b", algorithm=MD5, cnonce="1b538357", qop=auth, nc=00000001

             * */
            // yw old sip pass
            //string response = "c6226201d879e80e20c698fb584e5d7b";
            //string realm = "139.129.86.228";
            //string method = "REGISTER";
            //string uri = "sip:tt.hori-gz.com";
            //string username = "600013160907030@tt.hori-gz.com";
            //string password = "21218CCA77804D2BA1922C33E0151105";
            //string nonce = "cfde464b7e367939cec45964e6e7dfce";
            //string nc = "00000001";
            //string cnonce = "1b538357";
            //string qop = "auth";

            /*
  * 
Authorization: Digest username="600013160907030", realm="139.129.86.228", nonce="7374741d3757d7974e3addff09cd2ae5", 
uri="sip:tt.hori-gz.com", response="d7cf764338b894a44f782bdfea95964b", algorithm=MD5, cnonce="qge4GMlIny51Dand0ak5YbJ2gXdf31NvzIhw", qop=auth, nc=00000001

  * */
            // yw new sip pass
            string response = "d7cf764338b894a44f782bdfea95964b";
            string realm = "139.129.86.228";
            string method = "REGISTER";
            string uri = "sip:tt.hori-gz.com";
            string username = "600013160907030";
            string password = "21218CCA77804D2BA1922C33E0151105";
            string nonce = "7374741d3757d7974e3addff09cd2ae5";
            string nc = "00000001";
            string cnonce = "qge4GMlIny51Dand0ak5YbJ2gXdf31NvzIhw";
            string qop = "auth";

            string ha1 = String.Format("{0}:{1}:{2}", username, realm, password).ToMD5Hash();

            string ha2 = String.Format("{0}:{1}", method, uri).ToMD5Hash();

            string computedResponse = String.Format("{0}:{1}:{2}:{3}:{4}:{5}",
                                ha1, nonce, nc, cnonce, qop, ha2).ToMD5Hash();

            if (String.CompareOrdinal(response, computedResponse) == 0)
            {
                Console.Write("{0} {1} True", response, computedResponse);
            }
            else
            {
                Console.Write("{0} {1} False", response, computedResponse);
            }
            Console.ReadLine();
        }

        public static string ToMD5Hash(this string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }

            using (MD5 md5 = new MD5CryptoServiceProvider())
            {
                byte[] originalBytes = ASCIIEncoding.Default.GetBytes(value);
                byte[] encodedBytes = md5.ComputeHash(originalBytes);
                return BitConverter.ToString(encodedBytes).Replace("-", string.Empty).ToLower();
            }
        }
    }
}
