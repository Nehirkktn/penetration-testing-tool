function showPage(pageId) {
    let pages = document.querySelectorAll('.page');
    pages.forEach(p => p.classList.add('hidden'));
    document.getElementById(pageId).classList.remove('hidden');
}

function startScan() {
    let status = document.getElementById("status");
    status.innerText = "⏳ Tarama başlatıldı...";
    setTimeout(() => {
        status.innerText = "✅ Tarama tamamlandı!";
    }, 3000);
}
