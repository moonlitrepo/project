let secret_key = "LKS{lucu_dan_original}"
let username;
username = document.getElementById('username');
username.textContent = 'reno';

function submit() {
    let comentar = document.getElementById('input_comentar').value;
    let display_comentar = document.getElementById('comentar');
    display_comentar.innerHTML = comentar;
}