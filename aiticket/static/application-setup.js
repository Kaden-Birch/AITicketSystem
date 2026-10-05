'use strict';
const applicationSelector = document.querySelector('[data-application-kind]');
if (applicationSelector) {
  const showApplication = () => document.querySelectorAll('[data-application-fields]').forEach(section => {
    const active = section.dataset.applicationFields === applicationSelector.value;
    section.hidden = !active;
    section.querySelectorAll('input,select,textarea').forEach(field => { field.disabled = !active; });
  });
  applicationSelector.addEventListener('change', showApplication);
  showApplication();
}
