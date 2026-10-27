<script lang="ts">
  import { apiFetch } from '$lib/session.svelte';
  import type { IntegrationEngine, IntegrationTarget } from '$lib/types';

  let { engine, targets, onChanged } = $props<{
    engine: IntegrationEngine;
    targets: IntegrationTarget[];
    onChanged: () => Promise<void>;
  }>();

  let targetId = $state('');
  let username = $state('');
  let password = $state('');
  let saving = $state(false);
  let error = $state<string | undefined>();
  let success = $state<string | undefined>();

  let selectedTarget = $derived(
    targets.find((target: IntegrationTarget) => target.id === targetId)
  );

  $effect(() => {
    if (!targets.some((target: IntegrationTarget) => target.id === targetId)) {
      targetId = targets[0]?.id ?? '';
    }
  });

  async function replaceCredential(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (!selectedTarget) {
      return;
    }
    error = undefined;
    success = undefined;
    saving = true;
    try {
      await apiFetch(`/v1/admin/integration-targets/${selectedTarget.id}/credential`, {
        method: 'PUT',
        body: JSON.stringify({ username: username.trim() || undefined, password })
      });
      password = '';
      username = '';
      success = 'Nova credencial validada e armazenada no Vault.';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Não foi possível substituir a credencial.';
    } finally {
      password = '';
      saving = false;
    }
  }

  async function toggleEnabled(): Promise<void> {
    if (!selectedTarget) {
      return;
    }
    error = undefined;
    success = undefined;
    saving = true;
    try {
      await apiFetch(`/v1/admin/integration-targets/${selectedTarget.id}/enabled`, {
        method: 'PUT',
        body: JSON.stringify({ enabled: !selectedTarget.enabled })
      });
      success = selectedTarget.enabled ? 'Conexão pausada.' : 'Conexão ativada.';
      await onChanged();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Não foi possível atualizar a conexão.';
    } finally {
      saving = false;
    }
  }
</script>

{#if targets.length > 0}
  <section class="panel form-panel">
    <div class="panel-heading">
      <div>
        <p class="eyebrow">MANUTENÇÃO</p>
        <h2>Credencial e ativação</h2>
      </div>
    </div>
    {#if error}<p class="notice notice-error" role="alert">{error}</p>{/if}
    {#if success}<p class="notice notice-success" role="status">{success}</p>{/if}
    <label>
      Conexão
      <select bind:value={targetId}>
        {#each targets as target (target.id)}
          <option value={target.id}>{target.name} · {target.enabled ? 'ativa' : 'pausada'}</option>
        {/each}
      </select>
    </label>
    {#if selectedTarget}
      <form onsubmit={replaceCredential}>
        <div class="form-row">
          <label
            >Usuário (opcional)<input
              bind:value={username}
              maxlength="256"
              autocomplete="off"
            /></label
          >
          <label>
            Nova credencial
            <input bind:value={password} type="password" required autocomplete="new-password" />
          </label>
        </div>
        <button class="button button-primary" type="submit" disabled={saving}>
          {saving ? 'Validando…' : 'Testar e substituir credencial'}
        </button>
        <button class="text-button" type="button" onclick={toggleEnabled} disabled={saving}>
          {selectedTarget.enabled ? 'Pausar conexão' : 'Ativar conexão'}
        </button>
      </form>
    {/if}
    <small
      >Credenciais existentes nunca são recuperadas pela interface; a substituição é write-only.</small
    >
  </section>
{/if}
