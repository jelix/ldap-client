#!/bin/bash
APPDIR="/jelixapp/"
UNITTESTS_DIR="/jelixapp/tests/tests/"
APP_USER=userphp
APP_GROUP=groupphp

COMMAND="$1"
shift

if [ "$COMMAND" == "" ]; then
    echo "Error: command is missing"
    exit 1;
fi



function composerInstall() {
    if [ -f $APPDIR/composer.lock ]; then
        rm -f $APPDIR/composer.lock
    fi
    composer install --prefer-dist --no-progress --no-ansi --no-interaction --working-dir=$APPDIR
    chown -R $APP_USER:$APP_GROUP $APPDIR/vendor $APPDIR/composer.lock
}

function composerUpdate() {
    if [ -f $APPDIR/composer.lock ]; then
        rm -f $APPDIR/composer.lock
    fi
    composer update --prefer-dist --no-progress --no-ansi --no-interaction --working-dir=$APPDIR
    chown -R $APP_USER:$APP_GROUP $APPDIR/vendor $APPDIR/composer.lock
}


case $COMMAND in
    composer_install)
        composerInstall;;
    composer_update)
        composerUpdate;;
    unittests)
        UTCMD="cd $UNITTESTS_DIR/ && ../../vendor/bin/phpunit  $@"
        su $APP_USER -c "$UTCMD"
        ;;
    *)
        echo "wrong command"
        exit 2
        ;;
esac

