
let arrayMenu = ['Nasi Goreng','Ayam Goreng','Ayam Bakar','Bakso','Es Teh','Es susu'];
let arrayHarga = [10000,12000,12000,11000,3000,5000];
let ordered = [];

let areaMenu = document.getElementById('areaMenu');
let orderedMenu = document.getElementById('orderedMenu');
let totalOrder = document.getElementById('totalOrder')
let button = document.getElementById('button');

function renderMenu(){
    let html = `
        <ul class="list-group">
    `
    
    for (let i=0 ; i < arrayMenu.length ; i++){
        html += `
            <li class="list-group-item d-flex justify-content-between align-items-center">
                <div>
                    <h5 class="mb-0">${arrayMenu[i]}</h5>
                    <small>Rp.${arrayHarga[i]}</small>
                </div>
                <div>
                    <button onclick=addOrder(${i}) class="btn btn-primary btn-sm shadow">Tambah</button> 
                </div>
            </li>
        `
    }

    html += '</ul>';
    areaMenu.innerHTML = html;
}

function renderOrdered(){
    if (ordered.length === 0){
        orderedMenu.innerHTML = `
            <p>Kamu belum memesan apapun</p>
        `
        return;
    } 
    let html = `
        <ul class="list-group">
    `;
    let total = 0;
    for (let i=0 ; i < ordered.length ; i++){
        let index = ordered[i];

        let harga = arrayHarga[index];
        let pesanan = arrayMenu[index];
    
        total = total + harga

        html += `
            <li class="list-group-item d-flex justify-content-between align-items-center 
            list-group-item-success mb-1 rounded ">
                ${pesanan}  (Rp.${harga})
                <button class="btn btn-danger btn-sm">hapus</button>
            </li>
        `
       
    }

    html += '</ul>'
    orderedMenu.innerHTML = html
    totalOrder.innerHTML = `
            Rp.${total}
        `
}

function addOrder(index){
    ordered.push(index);
    renderOrdered();

}

function deleteOrder(){

}
renderMenu();
// renderOrdered();
