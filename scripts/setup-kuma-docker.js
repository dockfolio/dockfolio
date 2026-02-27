const io = require("socket.io-client");
const s = io("http://127.0.0.1:3001", {transports:["websocket"],reconnection:false});

s.on("connect", ()=>{
    console.log("connected");
    s.emit("login", {username:"admin",password:"appmanager2024",token:""}, (r)=>{
        console.log("login:", r.ok ? "OK" : r.msg);
        if(!r.ok){ process.exit(1); return; }
        addDockerMonitors(s, 1);
    });
});

function addDockerMonitors(s, dockerHostId) {
    const mons = [
        {name:"Docker: PromoForge API",docker_container:"promoforge-api-1",docker_host:dockerHostId,interval:60},
        {name:"Docker: PromoForge Worker",docker_container:"promoforge-worker-1",docker_host:dockerHostId,interval:60},
        {name:"Docker: BannerForge",docker_container:"bannerforge-bannerforge-1",docker_host:dockerHostId,interval:60},
    ];
    let i=0;
    function next(){
        if(i>=mons.length){console.log("All "+mons.length+" Docker monitors added");process.exit(0);return;}
        const m=mons[i];
        const data={
            name:m.name,
            type:"docker",
            docker_container:m.docker_container,
            docker_host:m.docker_host,
            interval:m.interval,
            retryInterval:30,
            maxretries:3,
            active:true,
            accepted_statuscodes:["200-299"],
        };
        s.emit("add", data, (r)=>{
            console.log((r.ok?"+":"x")+" "+m.name+(r.ok?"":(" ("+(r.msg||JSON.stringify(r))+")")));
            i++;
            setTimeout(next, 300);
        });
    }
    next();
}

s.on("connect_error",(e)=>{console.log("err:",e.message);process.exit(1);});
setTimeout(()=>{console.log("timeout");process.exit(1);},30000);
