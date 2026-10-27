<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch, waitForSession } from '$lib/session.svelte';
  import type { AuthConfig, IntegrationTarget } from '$lib/types';
  import IntegrationAccess from '$lib/IntegrationAccess.svelte';
  import IntegrationMaintenance from '$lib/IntegrationMaintenance.svelte';

  let targets = $state<IntegrationTarget[]>([]);
  let loading = $state(true);
  let saving = $state(false);
  let error = $state<string | undefined>();
  let success = $state<string | undefined>();
  let endpoint = $state<string | undefined>();
  let name = $state('');
  let host = $state('');
  let port = $state(6379);
  let username = $state('');
  let password = $state('');
  let tlsEnabled = $state(true);

  onMount(() => {
    void loadTargets();
  });

  async function loadTargets(): Promise<void> {
    await waitForSession();
    try {
      const response = await apiFetch('/v1/admin/integration-targets?engine=valkey');
      targets = (await response.json()) as IntegrationTarget[];
      const configResponse = await apiFetch('/v1/auth/config');
      const config = (await configResponse.json()) as AuthConfig;
      endpoint = config.mcp_endpoint;
    } catch (cause) {
      error =
        cause instanceof Error ? cause.message : 'Não foi possível carregar as conexões Valkey.';
    } finally {
      loading = false;
    }
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    error = undefined;
    success = undefined;
    saving = true;
    try {
      await apiFetch('/v1/admin/integration-targets', {
        method: 'POST',
        body: JSON.stringify({
          name: name.trim(),
          engine: 'valkey',
          host: host.trim(),
          port: Number(port),
          username: username.trim() || undefined,
          password,
          tls_enabled: tlsEnabled
        })
      });
      name = '';
      host = '';
      username = '';
      password = '';
      success =
        'Conexão validada. A credencial foi armazenada no Vault e não será exibida novamente.';
      await loadTargets();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Não foi possível registrar a conexão.';
    } finally {
      password = '';
      saving = false;
    }
  }
</script>

<svelte:head><title>Valkey · Valkey MCP</title></svelte:head>

<div class="page-heading">
  <div>
    <p class="eyebrow">CACHE AUTORIZADO</p>
    <h1>Valkey<span class="heading-period">.</span></h1>
    <p class="page-lede">
      Cadastre conexões Valkey para consultar e alterar dados via MCP sem compartilhar credenciais
      com o cliente de IA.
    </p>
  </div>
</div>

<section class="panel form-panel">
  <p class="eyebrow">MCP REMOTO</p>
  <h2>Conectar um cliente</h2>
  <p class="page-lede">
    Use OAuth do gateway. Não copie credenciais Valkey para a configuração do cliente de IA.
  </p>
  {#if endpoint}<code>{endpoint}</code>{/if}
</section>

<IntegrationAccess engine="valkey" scopePlaceholder="orders:" />

<IntegrationMaintenance engine="valkey" {targets} onChanged={loadTargets} />

{#if error}<p class="notice notice-error" role="alert">{error}</p>{/if}
{#if success}<p class="notice notice-success" role="status">{success}</p>{/if}

<div class="management-grid">
  <section class="panel table-panel">
    <div class="panel-heading">
      <div>
        <p class="eyebrow">CATÁLOGO</p>
        <h2>Conexões Valkey</h2>
      </div>
    </div>
    {#if loading}
      <div class="loading-panel">Carregando conexões…</div>
    {:else if targets.length === 0}
      <div class="empty-state compact-empty">
        <strong>Nenhuma conexão cadastrada</strong>
        <p>Adicione uma conexão pelo formulário ao lado.</p>
      </div>
    {:else}
      <div class="table-scroll">
        <table>
          <thead><tr><th>NOME</th><th>ENDPOINT</th><th>TLS</th><th>ESTADO</th></tr></thead>
          <tbody
            >{#each targets as target}<tr
                ><td><strong>{target.name}</strong></td><td class="mono-cell"
                  >{target.host}:{target.port}</td
                ><td>{target.tls_enabled ? 'Ativo' : 'Loopback'}</td><td
                  >{target.enabled ? 'Ativo' : 'Pausado'}</td
                ></tr
              >{/each}</tbody
          >
        </table>
      </div>
    {/if}
  </section>

  <section class="panel form-panel">
    <div class="panel-heading">
      <div>
        <p class="eyebrow">NOVA CONEXÃO</p>
        <h2>Registrar Valkey</h2>
      </div>
    </div>
    <form onsubmit={submit}>
      <label
        >Nome<input
          bind:value={name}
          required
          maxlength="80"
          placeholder="ex.: cache-prod"
        /></label
      >
      <div class="form-row">
        <label
          >Host privado<input
            bind:value={host}
            required
            maxlength="253"
            autocomplete="off"
            placeholder="valkey.internal"
          /></label
        ><label>Porta<input bind:value={port} type="number" min="1" max="65535" required /></label>
      </div>
      <label
        >Usuário ACL (opcional)<input
          bind:value={username}
          maxlength="256"
          autocomplete="off"
        /></label
      >
      <label
        >Senha<input
          bind:value={password}
          type="password"
          required
          autocomplete="new-password"
        /><small>Enviada somente ao gateway e ao Vault; nunca é devolvida pela API.</small></label
      >
      <label class="checkbox-label"
        ><input bind:checked={tlsEnabled} type="checkbox" /> Exigir TLS</label
      >
      <button class="button button-primary button-wide" type="submit" disabled={saving}
        >{saving ? 'Testando e registrando…' : 'Testar e registrar'}<span aria-hidden="true">→</span
        ></button
      >
    </form>
  </section>
</div>
