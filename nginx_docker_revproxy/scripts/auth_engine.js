function authorize_operation(r) {

  // Data to send to OPA
  let opa_data = {
      "operation" : r.headersIn["X-Operation"],
      "role" : "/" + r.headersIn["X-Role"],
      "uses_jwt" : r.headersIn["X-EnableJWT"],
      "token" : r.headersIn["Authorization"]
  }

  // HTTP package to send to OPA so it can correctly interpret the data
  var opts = {
      method: "POST",
      body: JSON.stringify(opa_data)
  };

  // Handles OPA's response
  r.subrequest("/_opa", opts, function(opa_res) {
      r.log("OPA Responded with status " + opa_res.status);
      r.log(JSON.stringify(opa_res));

      var body = JSON.parse(opa_res.responseText);

      // Checks OPA's response (which is in JSON)
      if (!body || !body.allow) {
          r.return(403);
          return;
      }

      r.return(opa_res.status); // Otherwise, returns the status code provided by OPA (usually 200)
  });

}

export default {authorize_operation}
