(()=>{
  const q=id=>document.getElementById(id);
  const gate=q('appGate'), dash=q('dashboard'), notice=q('gateNotice');
  const enc=new TextEncoder();
  async function sha(v){const b=await crypto.subtle.digest('SHA-256',enc.encode(v));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}
  function currentUser(){try{return JSON.parse(localStorage.getItem('bdto_app_user')||'null')}catch{return null}}
  function setScreen(logged,user){gate.classList.toggle('hidden',logged);dash.classList.toggle('hidden',!logged);document.body.classList.toggle('gate-active',!logged);if(logged)q('appUserBadge').textContent=`Masuk sebagai ${user||'Buzzer1'}`}
  function makeLightning(){const field=q('lightningField');if(!field||field.children.length)return;const spots=[[8,16,.58,-18,4.8,-.4],[14,37,.42,12,3.9,-1.1],[22,10,.46,-8,5.6,-2.2],[28,29,.34,19,4.3,-.8],[35,18,.52,-15,6.1,-3.4],[42,8,.38,10,4.7,-2.8],[48,26,.61,-10,5.2,-1.9],[57,13,.43,17,4.2,-.2],[64,31,.5,-21,5.8,-4.1],[72,9,.38,8,4.6,-1.5],[79,24,.55,-12,6.4,-2.5],[88,14,.47,18,4.1,-3.2],[94,36,.36,-9,5.4,-.7],[10,62,.39,14,5.1,-2.9],[19,79,.52,-20,6.2,-4.7],[31,67,.35,7,4.4,-1.7],[41,86,.47,-13,5.6,-3.8],[53,72,.41,21,4.8,-.9],[63,90,.56,-11,6.3,-2.1],[74,68,.35,16,4.5,-3.5],[84,82,.5,-16,5.7,-1.2],[93,61,.39,10,4.9,-4.4],[5,91,.32,-8,6.5,-2.6],[97,92,.43,14,5.3,-.5]];spots.forEach(([x,y,sc,r,d,delay])=>{const b=document.createElement('i');b.className='mini-lightning';b.style.setProperty('--x',x+'%');b.style.setProperty('--y',y+'%');b.style.setProperty('--s',sc);b.style.setProperty('--r',r+'deg');b.style.setProperty('--d',d+'s');b.style.setProperty('--delay',delay+'s');field.appendChild(b)})}
  function msg(t,ok=false){notice.textContent=t;notice.style.color=ok?'#7cf2b1':'#ffb6c4'}
  q('showRegisterBtn').onclick=()=>{q('loginForm').classList.add('hidden');q('registerForm').classList.remove('hidden');msg('')};
  q('showLoginBtn').onclick=()=>{q('registerForm').classList.add('hidden');q('loginForm').classList.remove('hidden');msg('')};
  q('appRegisterBtn').onclick=async()=>{const user=q('appRegisterUser').value.trim(),pw=q('appRegisterPassword').value;if(user.length<2)return msg('Nama pengguna minimal 2 karakter.');if(pw.length<6)return msg('Password minimal 6 karakter.');localStorage.setItem('bdto_app_user',JSON.stringify({user,hash:await sha(pw)}));q('appLoginUser').value=user;q('appLoginPassword').value='';q('registerForm').classList.add('hidden');q('loginForm').classList.remove('hidden');msg('Akun akses dashboard dibuat. Silakan login.',true)};
  q('appLoginBtn').onclick=async()=>{const saved=currentUser();if(!saved)return msg('Belum ada akun akses. Klik “Daftar sekarang” terlebih dahulu.');const user=q('appLoginUser').value.trim(),pw=q('appLoginPassword').value;if(user!==saved.user||await sha(pw)!==saved.hash)return msg('ID atau password dashboard tidak cocok.');sessionStorage.setItem('bdto_app_logged_in','1');setScreen(true,saved.user);startTyping()};
  q('appLogoutBtn').onclick=()=>{sessionStorage.removeItem('bdto_app_logged_in');setScreen(false);q('appLoginPassword').value='';msg('')};
  let typingRun=0;
  function startTyping(){
    const el=q('typingTitle'); if(!el)return;
    const run=++typingRun, full='BUZZER DIVTELEGRAM ONE';
    let i=0, deleting=false;
    el.textContent='';
    const step=()=>{
      if(run!==typingRun)return;
      if(!deleting){
        i++; el.textContent=full.slice(0,i);
        if(i>=full.length){deleting=true;return setTimeout(step,1500)}
        return setTimeout(step,90);
      }
      i--; el.textContent=full.slice(0,i);
      if(i<=0){deleting=false;return setTimeout(step,450)}
      setTimeout(step,45);
    };
    step();
  }

  const liveReviews=[
    {text:'Wah, aplikasi ini bagus banget dan nyaman digunakan 🔥',avatar:'avatar-1.svg'},
    {text:'Keren banget aplikasinya, tampilannya simpel dan gampang digunakan 😍',avatar:'avatar-2.svg'},
    {text:'Baru coba login, ternyata aplikasinya bagus banget 👍',avatar:'avatar-3.svg'},
    {text:'Mantap, aksesnya cepat dan aplikasinya enak banget digunakan ⚡',avatar:'avatar-4.svg'},
    {text:'Nggak nyangka sebagus ini, aplikasinya simpel dan nyaman dipakai ✨',avatar:'avatar-5.svg'}
  ];
  let liveReviewIndex=0, liveTimer=null;
  function startLiveReviews(){
    const toast=q('liveActivityToast'), text=q('liveActivityText'), avatar=q('liveActivityAvatar');
    if(!toast||!text||!avatar||liveTimer)return;
    const cycle=()=>{
      const item=liveReviews[liveReviewIndex%liveReviews.length];
      toast.classList.remove('show');
      setTimeout(()=>{
        text.textContent=item.text;
        avatar.src=item.avatar;
        toast.classList.add('show');
      },280);
      setTimeout(()=>toast.classList.remove('show'),3900);
      liveReviewIndex=(liveReviewIndex+1)%liveReviews.length;
    };
    setTimeout(cycle,650);
    liveTimer=setInterval(cycle,4700);
  }

  makeLightning();
  startLiveReviews();
  const saved=currentUser();if(saved)q('appLoginUser').value=saved.user;
  const logged=sessionStorage.getItem('bdto_app_logged_in')==='1'&&!!saved;setScreen(logged,saved?.user);if(logged)startTyping();
})();
