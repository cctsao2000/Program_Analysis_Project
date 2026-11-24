package org.owasp.benchmark.testcode;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.esapi.ESAPI;

public class ToySlice {
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("name");
        String safe = ESAPI.encoder().encodeForHTML(param);
        response.getWriter().println(safe);
    }
}
