const submit = document.querySelector('#addJobsButton');
const addForm = submit?.closest('form');
const addStatus = document.querySelector('#addJobsStatus');
const loadingDialog = document.querySelector('#addJobsLoading');
const resultDialog = document.querySelector('#addJobsResult');
const checkLoadingDialog = document.querySelector('#checkJobLoading');
const checkResultDialog = document.querySelector('#checkJobResult');
let addingJobs = false;
let checkingJob = false;

addForm?.addEventListener('submit', event => {
  if (!addForm.reportValidity()) { event.preventDefault(); return; }
  if (addingJobs) { event.preventDefault(); return; }
  addingJobs = true;
  submit.disabled = true;
  submit.textContent = 'Adding…';
  if (addStatus) addStatus.textContent = 'Adding job. This may take a moment.';
  loadingDialog?.showModal();
  document.body.classList.add('modal-active');
});
loadingDialog?.addEventListener('cancel', event => event.preventDefault());
resultDialog?.addEventListener('close', () => document.body.classList.remove('modal-active'));
if (resultDialog) {
  resultDialog.showModal();
  document.body.classList.add('modal-active');
  document.querySelector('#closeAddJobsResult')?.focus();
}
for (const form of document.querySelectorAll('.check-job-form')) {
  form.addEventListener('submit', event => {
    if (checkingJob) { event.preventDefault(); return; }
    checkingJob = true;
    form.querySelector('button[type="submit"]').disabled = true;
    document.querySelector('#checkJobLoadingTitle').textContent = `Checking Job ${form.dataset.jobNumber}`;
    checkLoadingDialog?.showModal();
    document.body.classList.add('modal-active');
  });
}
checkLoadingDialog?.addEventListener('cancel', event => event.preventDefault());
checkResultDialog?.addEventListener('close', () => document.body.classList.remove('modal-active'));
if (checkResultDialog) {
  checkResultDialog.showModal();
  document.body.classList.add('modal-active');
  document.querySelector('#closeCheckJobResult')?.focus();
}
window.addEventListener('pageshow', event => {
  if (!event.persisted) return;
  loadingDialog?.close();
  checkLoadingDialog?.close();
  addingJobs = false;
  checkingJob = false;
  for (const button of document.querySelectorAll('.check-job-form button[type="submit"]')) button.disabled = false;
  if (submit) {
    submit.disabled = false;
    submit.textContent = 'Add Job';
  }
  if (addStatus) addStatus.textContent = '';
  if (!resultDialog?.open && !checkResultDialog?.open) document.body.classList.remove('modal-active');
});

const searchForm = document.querySelector('#jobSearchForm');
const searchInput = document.querySelector('#jobSearch');
let searchTimer;
searchInput?.addEventListener('input', () => {
  clearTimeout(searchTimer);
  const length = searchInput.value.trim().length;
  if (length >= 3 || length === 0) searchTimer = setTimeout(() => searchForm.requestSubmit(), 500);
});
document.querySelector('#clearSearch')?.addEventListener('click', () => {
  searchInput.value = '';
  searchForm.requestSubmit();
});
