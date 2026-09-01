"use strict";

function updateJiraForm(form) {
  const shouldPost = form.querySelector("input[name='post_to_jira']:checked")?.value === "yes";
  const fields = form.querySelector("[data-jira-ticket-fields]");
  const ticket = form.querySelector("input[name='jira_ticket']");
  const submit = form.querySelector("[data-jira-post-submit]");
  if (fields) fields.hidden = !shouldPost;
  if (ticket) {
    ticket.disabled = !shouldPost;
    ticket.required = shouldPost;
  }
  if (submit) submit.disabled = !shouldPost;
}

async function copyReplayResults(button) {
  const source = document.getElementById(button.dataset.copyTarget);
  if (!source?.value) return;
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(source.value);
  } catch (_error) {
    const helper = document.createElement("textarea");
    helper.value = source.value;
    helper.readOnly = true;
    helper.className = "replay-copy-helper";
    document.body.appendChild(helper);
    helper.select();
    document.execCommand("copy");
    helper.remove();
  }
  button.textContent = "Copied";
  window.setTimeout(() => { button.textContent = original; }, 1800);
}

document.addEventListener("change", (event) => {
  const choice = event.target.closest("[data-jira-post-form] input[name='post_to_jira']");
  if (choice) updateJiraForm(choice.form);
});

document.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-copy-target]");
  if (button) copyReplayResults(button);
});

document.querySelectorAll("[data-jira-post-form]").forEach(updateJiraForm);
