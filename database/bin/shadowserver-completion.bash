# bash completion for the 'shadowserver' command (installed by deploy.sh)
_shadowserver() {
  local cur prev cmd
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmd="${COMP_WORDS[1]-}"

  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "run check status logs schedule deploy help man version" -- "$cur"))
    return
  fi
  case "$prev" in
    --stage)    COMPREPLY=($(compgen -W "all email load" -- "$cur")); return ;;
    --days|--workers|--schedule) return ;;
    --env-file) COMPREPLY=($(compgen -f -- "$cur")); return ;;
  esac
  case "$cmd" in
    run|-*)  COMPREPLY=($(compgen -W "--stage --days --workers --quiet --verbose --check --env-file --help --man" -- "$cur")) ;;
    logs|log) COMPREPLY=($(compgen -W "-f --follow" -- "$cur")) ;;
    schedule|cron) COMPREPLY=($(compgen -W "show off --help 06:00 06:30 07:00" -- "$cur")) ;;
    deploy)  COMPREPLY=($(compgen -W "--schedule --unschedule --remove-container --help" -- "$cur")) ;;
  esac
}
complete -F _shadowserver shadowserver
