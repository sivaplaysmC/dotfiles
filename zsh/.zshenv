source "$HOME/.cargo/env"


# If you come from bash you might have to change your $PATH.
export PATH=$HOME/bin:$HOME/.local/bin:/usr/local/bin:$PATH


export ANDROID_HOME=/opt/android-sdk

export PATH=$ANDROID_HOME/tools:$PATH
export PATH=$ANDROID_HOME/platform-tools:$PATH
export PATH=$ANDROID_HOME/tools/bin:$PATH
export PATH=$ANDROID_HOME/build-tools/35.0.0/:$PATH


export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"

source "/home/hknhmr/.deno/env"

export PATH=~/.pyenv/shims:$PATH


export PATH="$(go env GOPATH)/bin:$PATH"

# Frikkin firstsource
export PATH="$PATH:/home/hknhmr/.dotnet/tools"

export FZF_POPUP_OPTS='--tmux "top,60%,40%" --reverse --margin 0,2,1,2 --border none --track --multi  --info inline-right --input-border=none --separator "-+"'

export FZF_POPUP_OPTS=(
  --tmux "top,60%,40%"
  --reverse
  --margin 0,2,1,2
  --border none
  --track
  --multi
  --info inline-right
  --input-border=none
  --separator "+-"
)

export FZF_COMPLETION_TRIGGER=','
