const io = require("socket.io-client");
const s = io("http://127.0.0.1:3001", {transports:["websocket"],reconnection:false});

s.on("connect", ()=>{
    console.log("connected");
    s.emit("login", {username:"admin",password:"appmanager2024",token:""}, (r)=>{
        console.log("login:", r.ok ? "OK" : r.msg);
        if(!r.ok){ process.exit(1); return; }

        // addStatusPage(title, slug, callback) — separate args!
        console.log("Creating status page...");
        s.emit("addStatusPage", "Crelvo Services", "status", (sr) => {
            console.log("add result:", JSON.stringify(sr));
            if(!sr.ok){ process.exit(1); return; }

            // saveStatusPage(slug, config, imgDataUrl, publicGroupList, callback)
            const config = {
                slug: "status",
                title: "Crelvo Services",
                description: "Real-time status of all services",
                theme: "dark",
                published: true,
                showTags: false,
                showPoweredBy: false,
                showCertificateExpiry: false,
                footerText: "",
                customCSS: "",
                googleAnalyticsId: "",
                domainNameList: [],
            };

            const publicGroupList = [
                {
                    name: "SaaS Applications",
                    monitorList: [
                        {id:1, sendUrl:true},
                        {id:2, sendUrl:true},
                        {id:3, sendUrl:true},
                        {id:4, sendUrl:true},
                        {id:5, sendUrl:true},
                    ],
                },
                {
                    name: "Tools & Services",
                    monitorList: [
                        {id:6, sendUrl:true},
                        {id:7, sendUrl:true},
                        {id:8, sendUrl:true},
                    ],
                },
                {
                    name: "Websites",
                    monitorList: [
                        {id:9, sendUrl:true},
                        {id:10, sendUrl:true},
                        {id:11, sendUrl:true},
                        {id:12, sendUrl:true},
                        {id:13, sendUrl:true},
                    ],
                },
                {
                    name: "Infrastructure",
                    monitorList: [
                        {id:14, sendUrl:false},
                        {id:15, sendUrl:false},
                        {id:16, sendUrl:false},
                        {id:17, sendUrl:false},
                    ],
                },
            ];

            console.log("Saving status page config with groups...");
            s.emit("saveStatusPage", "status", config, "", publicGroupList, (res) => {
                console.log("save result:", JSON.stringify(res));
                if(res.ok) console.log("Status page created successfully!");
                process.exit(res.ok ? 0 : 1);
            });
        });
    });
});

s.on("connect_error",(e)=>{console.log("err:",e.message);process.exit(1);});
setTimeout(()=>{console.log("timeout");process.exit(1);},20000);
