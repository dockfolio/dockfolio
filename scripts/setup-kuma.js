const io = require("socket.io-client");
const s = io("http://127.0.0.1:3001", {transports:["websocket"],reconnection:false});

s.on("connect", ()=>{
    console.log("connected");
    s.emit("login", {username:"admin",password:"appmanager2024",token:""}, (r)=>{
        console.log("login:", r.ok ? "OK" : r.msg);
        if(!r.ok){ process.exit(1); return; }
        addMonitors(s);
    });
});

function addMonitors(s) {
    const mons = [
        {name:"PromoForge",url:"https://promoforge.app",interval:60},
        {name:"PromoForge API",url:"https://promoforge.app/health",interval:60},
        {name:"BannerForge",url:"https://bannerforge.app",interval:60},
        {name:"Headshot AI",url:"https://bewerbungsfotos-ai.de",interval:60},
        {name:"AbschlussCheck",url:"https://abschlusscheck.de",interval:60},
        {name:"LohnCheck",url:"https://lohnpruefung.de",interval:120},
        {name:"SacredLens",url:"https://sacredlens.de",interval:120},
        {name:"Plausible",url:"https://plausible.theadhdmind.org",interval:120},
        {name:"TheADHDMind",url:"https://theadhdmind.org",interval:300},
        {name:"Creative Programmer",url:"https://thecreativeprogrammer.dev",interval:300},
        {name:"Crelvo",url:"https://crelvo.dev",interval:300},
        {name:"Old World Logos",url:"https://oldworldlogos.com",interval:300},
        {name:"AgoraHoch3",url:"https://agorahoch3.org",interval:300},
        {name:"App Manager Dashboard",url:"https://admin.crelvo.dev/health",interval:120},
    ];
    let i=0;
    function next(){
        if(i>=mons.length){console.log("All "+mons.length+" monitors added");process.exit(0);return;}
        const m=mons[i];
        const data={
            name:m.name,
            type:"http",
            url:m.url,
            method:"GET",
            interval:m.interval,
            retryInterval:30,
            maxretries:3,
            active:true,
            accepted_statuscodes:["200-299"],
        };
        s.emit("add", data, (r)=>{
            console.log((r.ok?"+":"x")+" "+m.name+(r.ok?"":(" ("+(r.msg||"error")+")")));
            i++;
            setTimeout(next, 300);
        });
    }
    next();
}
s.on("connect_error",(e)=>{console.log("err:",e.message);process.exit(1);});
setTimeout(()=>{console.log("timeout");process.exit(1);},60000);
