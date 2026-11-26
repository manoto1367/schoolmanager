var V="cm-v5",FILES=["./","index.html","manifest.webmanifest","icon.png","icon-192.png","icon-maskable-192.png","icon-maskable-512.png"];
self.addEventListener("install",function(e){e.waitUntil(caches.open(V).then(function(c){return c.addAll(FILES)}).then(function(){return self.skipWaiting()}))});
self.addEventListener("activate",function(e){e.waitUntil(caches.keys().then(function(k){return Promise.all(k.filter(function(x){return x!==V}).map(function(x){return caches.delete(x)}))}).then(function(){return self.clients.claim()}))});
self.addEventListener("fetch",function(e){
 var r=e.request,u=new URL(r.url);
 if(r.method!=="GET"||u.origin!==location.origin)return; // Supabase و سایر درخواست‌های بیرونی دست‌نخورده می‌مانند
 e.respondWith(fetch(r).then(function(res){var cp=res.clone();caches.open(V).then(function(c){c.put(r,cp)});return res}).catch(function(){return caches.match(r).then(function(m){return m||(r.mode==="navigate"?caches.match("index.html"):undefined)})}));
});
