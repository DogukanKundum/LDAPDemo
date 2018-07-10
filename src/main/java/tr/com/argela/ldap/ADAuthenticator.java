package tr.com.argela.ldap;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

public class ADAuthenticator {

    private String domain;
    private String ldapHost;
    private String searchBase;
    private String accountName;

    public ADAuthenticator() {
        this.domain = "argela.com.tr";
        this.ldapHost = "ldap://arge-lolan.argela.com.tr:389";
        this.searchBase = "CN=users,DC=argela,DC=com,DC=tr";
        this.accountName = "sAMAccountName";
    }

    public ADAuthenticator(String domain, String ldapHost, String searchBase, String accountName) {
        this.domain = domain;
        this.ldapHost = ldapHost;
        this.searchBase = searchBase;
        this.accountName = accountName;
    }

    public Map authenticate(String user, String pass) {
        String returnedAtts[] = {"sn", "givenName", "mail"};
        String searchFilter = "(&(objectClass=Person)(" + accountName + "=" + user + "))";

        //Create the search controls
        SearchControls searchCtls = new SearchControls();
        searchCtls.setReturningAttributes(returnedAtts);

        //Specify the search scope
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapHost);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, user + "@" + domain);
        env.put(Context.SECURITY_CREDENTIALS, pass);

        LdapContext ctxGC = null;

        try {
            ctxGC = new InitialLdapContext(env, null);
            //Search objects in GC using filters
            NamingEnumeration answer = ctxGC.search(searchBase, searchFilter, searchCtls);
            System.out.println("answer : " + answer);
            while (answer.hasMoreElements()) {
                SearchResult sr = (SearchResult) answer.next();
                Attributes attrs = sr.getAttributes();
                Map amap = null;
                if (attrs != null) {
                    amap = new HashMap();
                    NamingEnumeration ne = attrs.getAll();
                    while (ne.hasMore()) {
                        Attribute attr = (Attribute) ne.next();
                        amap.put(attr.getID(), attr.get());
                    }
                    ne.close();
                }
                return amap;
            }
        } catch (NamingException ex) {
            System.out.println(ex);
        }

        return null;
    }

    public static void main(String args[]) {

        Properties prop = new Properties();
        FileInputStream input = null;

        try {
            String path = System.getenv("SSG_HOME") + System.getProperty("file.separator") + "resources" + System.getProperty("file.separator");

            input = new FileInputStream(path + "ldap.properties");
            prop.load(input);

            System.out.println("--------------------PROPERTIES-----------------------");
            // set the properties value
            System.out.println(prop.getProperty("domain"));
            System.out.println(prop.getProperty("ldapHost"));
            System.out.println(prop.getProperty("searchBase"));
            System.out.println(prop.getProperty("username"));
            System.out.println(prop.getProperty("password"));
            System.out.println(prop.getProperty("accountName"));

            System.out.println("-------------------------------------------------------------");

        } catch (IOException io) {
            io.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }

        try {
            ADAuthenticator adAuthenticator = new ADAuthenticator(prop.getProperty("domain"), prop.getProperty("ldapHost"), prop.getProperty("searchBase"), prop.getProperty("accountName"));
            Map map = adAuthenticator.authenticate(prop.getProperty("username"), prop.getProperty("password"));
            if (map == null) System.out.println("Result Map : " + map.size());
            else System.out.println("Result map : " + map.size());
        } catch (Exception e) {
            System.out.println(e);
        }

    }
}
