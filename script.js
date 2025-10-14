// football-club-system/script.js

// Get elements
const form = document.getElementById('playerForm');
const playerList = document.getElementById('playerList');

// Load saved players from local storage
let players = JSON.parse(localStorage.getItem('players')) || [];

// Display players on load
displayPlayers();

// Handle form submission
form.addEventListener('submit', (e) => {
  e.preventDefault();

  const name = document.getElementById('name').value;
  const position = document.getElementById('position').value;
  const age = document.getElementById('age').value;

  if (!name || !position || !age) return alert('Please fill in all fields');

  const player = { id: Date.now(), name, position, age };
  players.push(player);
  localStorage.setItem('players', JSON.stringify(players));

  form.reset();
  displayPlayers();
});

// Display player list
function displayPlayers() {
  playerList.innerHTML = '';
  players.forEach((p) => {
    const li = document.createElement('li');
    li.textContent = `${p.name} - ${p.position} (${p.age} yrs)`;
    const delBtn = document.createElement('button');
    delBtn.textContent = '❌';
    delBtn.onclick = () => deletePlayer(p.id);
    li.appendChild(delBtn);
    playerList.appendChild(li);
  });
}

// Delete player
function deletePlayer(id) {
  players = players.filter((p) => p.id !== id);
  localStorage.setItem('players', JSON.stringify(players));
  displayPlayers();
    }
