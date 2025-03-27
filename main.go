http:
  routers:
    totoRouter:
      rule: "PathPrefix(`/toto`)"
      service: totoService
      entryPoints:
        - web
      middlewares:
        - stripApiPrefix
        - uppercaseMiddleware
  services:
    totoService:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:9099"



  middlewares:
    stripApiPrefix:
      stripPrefix:
        prefixes:
          - "/toto"
    uppercaseMiddleware:
      plugin:
        traefikbodyrequesttransformerx: 

          jwksURL: "http://localhost:8081/realms/test/protocol/openid-connect/certs"

          clientId: "client"
          tokenUrl: "http://localhost:8081/realms/test/protocol/openid-connect/token"
          secret: "M1B3eLDAsZfQ9XIpC4CXLTuwZnulKE7J"

          secureType: "oauth2" #Basic, Static (HeaderName, Value), Oauth2

          transformations:
            - enable: true
              secure: true
              method: "GET"
              url: "/api/lower"
              jspathRequest: |
                {
                  "usrXXXX": "$.info.toto",
                    "claim":"_$c.Jti"

                }
            - enable: true
              secure: false
              method: "GET"
              url: "/api/data"
              jspathRequest: |
                {
                  "usr": "$.info.toto",
                  "mc": {
                    "id": "_$q.query1",
                    "jjoX": "_$h.header1"
                  }
                }
            - enable: true
              secure: false
              sendCredentials: false
              method: "GET"
              url: "/api/headers"
              addHeaders:
                X-Custom-Header: "MyValue"
                User-Agent: "Traefik-Modified"
                User-Agent2: "$.eee"
                User-Agent3: "_$q.q1"
                User-Agent4: "_$c.Jti"
              removeHeaders:
                - "Ahmed"
              
