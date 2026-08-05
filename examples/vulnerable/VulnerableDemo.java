// Vulnerable Java sample — DO NOT use in production
import java.io.*;
import java.sql.*;
import javax.servlet.http.*;
import javax.xml.parsers.DocumentBuilderFactory;

public class VulnerableDemo {
    public ResultSet findUser(Connection conn, String userId) throws Exception {
        Statement st = conn.createStatement();
        String q = "SELECT * FROM users WHERE id = " + userId;
        return st.executeQuery(q);
    }

    public void run(String name) throws Exception {
        Runtime.getRuntime().exec("ping " + name);
    }

    public Object load(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }

    public void parseXml(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(in);
    }

    public void echo(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        resp.getWriter().print(name);
    }
}
