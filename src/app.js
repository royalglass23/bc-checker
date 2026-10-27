const file = document.querySelector('#csvFile');
const textarea = document.querySelector('#jobNumbers');
if (file && textarea) file.addEventListener('change', async () => {
  const selected = file.files?.[0];
  if (selected) textarea.value = await selected.text();
});
