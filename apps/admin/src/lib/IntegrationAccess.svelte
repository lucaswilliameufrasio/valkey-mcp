<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch, waitForSession } from '$lib/session.svelte';
  import type { AccessLevel, IntegrationEngine, IntegrationTarget, Principal } from '$lib/types';

  let { engine, scopePlaceholder } = $props<{
    engine: IntegrationEngine;
    scopePlaceholder: string;
  }>();

  let principals = $state<Principal[]>([]);
  let targets = $state<IntegrationTarget[]>([]);
  let principalId = $state('');
  let targetId = $state('');
  let accessLevel = $state<AccessLevel>('read');
  let resourceScope = $state('');
  let saving = $state(false);
  let error = $state<string | undefined>();
  let success = $state<string | undefined>();

  onMount(() => {
    void loadOptions();
  });

  async function loadOptions(): Promise<void> {
    await waitForSession();
    try {
      const [principalResponse, targetResponse] = await Promise.all([
        apiFetch('/v1/admin/principals'),
        apiFetch(`/v1/admin/integration-targets?engine=${engine}`)
      ]);
      principals = (await principalResponse.json()) as Principal[];
      targets = (await targetResponse.json()) as IntegrationTarget[];
      principalId = principals[0]?.id ?? '';
      targetId = targets[0]?.id ?? '';
    } catch (cause) {
      error =
        cause instanceof Error ? cause.message : 'Não foi possível carregar as opções de acesso.';
    }
  }

  async function saveGrant(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    error = undefined;
    success = undefined;
    saving = true;
    try {
      await apiFetch(`/v1/admin/principals/${principalId}/integration-grants/${targetId}`, {
        method: 'PUT',
        body: JSON.stringify({ access_level: accessLevel, resource_scope: resourceScope.trim() })
      });
      success = 'Acesso atualizado.';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Não foi possível atualizar o acesso.';
    } finally {
      saving = false;
    }
  }

  async function revokeGrant(): Promise<void> {
    error = undefined;
    success = undefined;
    saving = true;
    try {
      await apiFetch(`/v1/admin/principals/${principalId}/integration-grants/${targetId}`, {
        method: 'DELETE'
      });
      success = 'Acesso revogado.';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Não foi possível revogar o acesso.';
    } finally {
      saving = false;
    }
  }
</script>

<section class="panel form-panel">
  <div class="panel-heading">
    <div>
      <p class="eyebrow">ACESSO EXPLÍCITO</p>
      <h2>Conceder acesso</h2>
    </div>
  </div>
  {#if error}<p class="notice notice-error" role="alert">{error}</p>{/if}
  {#if success}<p class="notice notice-success" role="status">{success}</p>{/if}
  {#if principals.length === 0 || targets.length === 0}
    <div class="empty-state compact-empty">
      <strong>Faltam usuários ou conexões</strong>
      <p>Cadastre uma conexão e autentique cada usuário antes de conceder acesso.</p>
    </div>
  {:else}
    <form onsubmit={saveGrant}>
      <label
        >Usuário<select bind:value={principalId}
          >{#each principals as principal}<option value={principal.id}
              >{principal.display_name ?? principal.email ?? principal.subject}</option
            >{/each}</select
        ></label
      >
      <label
        >Conexão<select bind:value={targetId}
          >{#each targets as target}<option value={target.id}
              >{target.name} · {target.host}:{target.port}</option
            >{/each}</select
        ></label
      >
      <div class="form-row">
        <label
          >Permissão<select bind:value={accessLevel}
            ><option value="read">Somente leitura</option><option value="write"
              >Leitura e escrita</option
            ></select
          ></label
        >
        <label
          >Escopo<input
            bind:value={resourceScope}
            required
            maxlength="256"
            placeholder={scopePlaceholder}
          /></label
        >
      </div>
      <button class="button button-primary button-wide" type="submit" disabled={saving}
        >{saving ? 'Salvando…' : 'Salvar permissão'}<span aria-hidden="true">→</span></button
      >
      <button class="text-button" type="button" onclick={revokeGrant} disabled={saving}
        >Revogar acesso selecionado</button
      >
    </form>
  {/if}
</section>
