const file = document.querySelector('#jobFile');
const textarea = document.querySelector('#jobNumbers');
const status = document.querySelector('#fileStatus');
const submit = document.querySelector('#addJobsButton');

if (file && textarea && status && submit) file.addEventListener('change', async () => {
  const selected = file.files?.[0];
  if (!selected) return;
  textarea.value = '';
  submit.disabled = true;
  status.textContent = 'Reading file…';
  try {
    if (selected.size > 1024 * 1024) throw new Error('File must be 1 MB or smaller.');
    const extension = selected.name.split('.').pop()?.toLowerCase();
    if (extension === 'csv') {
      textarea.value = await selected.text();
    } else if (extension === 'xlsx') {
      if (typeof readXlsxFile !== 'function') throw new Error('Spreadsheet reader is unavailable. Please reload the page.');
      const sheets = await readXlsxFile(selected);
      const rows = sheets[0]?.data ?? [];
      if (!rows.length) throw new Error('The first worksheet is empty.');
      const first = rows[0].map(cell => String(cell ?? '').trim());
      const headerIndex = first.findIndex(cell => /^(?:job\s*(?:number|no|id)|generated_job_id)$/i.test(cell));
      const column = headerIndex >= 0 ? headerIndex : 0;
      const values = (headerIndex >= 0 ? rows.slice(1) : rows)
        .map(row => String(row[column] ?? '').trim()).filter(Boolean);
      if (values.some(value => !/^[A-Za-z0-9-]{1,30}$/.test(value))) {
        throw new Error('The job number column contains an invalid value.');
      }
      textarea.value = [...new Set(values)].join('\n');
    } else {
      throw new Error('Choose a CSV or XLSX file.');
    }
    if (!textarea.value.trim()) throw new Error('No job numbers found in the file.');
    if (textarea.value.length > 20_000) throw new Error('File contains too much data. Upload up to 50 jobs at a time.');
    status.textContent = `${selected.name} loaded. Review the job numbers, then add them to monitoring.`;
  } catch (error) {
    textarea.value = '';
    status.textContent = error.message || 'Could not read the file.';
  } finally {
    submit.disabled = false;
  }
});
