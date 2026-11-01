"""
Tests for the AI Guard plugin. They use CTFd's own test helpers, so run them from a CTFd
checkout with the plugin installed into CTFd/plugins/ai_guard:

    python -m pytest CTFd/plugins/ai_guard/tests -p no:randomly
"""

import datetime

import pytest
from freezegun import freeze_time

from CTFd.models import Solves, Submissions, Teams, Users
from CTFd.plugins.ai_guard import config, notify
from CTFd.plugins.ai_guard.models import (
    AIGuardEvent,
    AIGuardNotice,
    AIGuardShame,
    AIGuardState,
    AIGuardView,
)
from CTFd.utils import set_config
from CTFd.utils.security.auth import generate_user_token
from tests.helpers import (
    create_ctfd,
    destroy_ctfd,
    gen_challenge,
    gen_flag,
    gen_team,
    login_as_user,
    register_user,
)


@pytest.fixture(autouse=True)
def frozen_submission_dates():
    # Submissions.date defaults to the real datetime.utcnow bound at import time, which
    # freezegun can not patch. Resolve it at call time so solves follow the frozen clock.
    default = Submissions.__table__.c.date.default
    original = default.arg
    default.arg = lambda ctx: datetime.datetime.utcnow()
    yield
    default.arg = original


def make_app(user_mode="users"):
    return create_ctfd(user_mode=user_mode, enable_plugins=True)


def make_challenges(app, count=6):
    ids = []
    for i in range(count):
        chal = gen_challenge(app.db, name=f"chal{i}")
        gen_flag(app.db, challenge_id=chal.id, content=f"flag{{{i}}}")
        ids.append(chal.id)
    return ids


def submit(client, challenge_id, flag):
    r = client.post(
        "/api/v1/challenges/attempt",
        json={"challenge_id": challenge_id, "submission": flag},
    )
    return r.get_json()["data"]["status"]


def events(kind=None):
    q = AIGuardEvent.query
    if kind:
        q = q.filter_by(kind=kind)
    return q.order_by(AIGuardEvent.id).all()


def state_for(user_id=None, team_id=None):
    if team_id is not None:
        return AIGuardState.query.filter_by(team_id=team_id).first()
    return AIGuardState.query.filter_by(user_id=user_id).first()


def test_plugin_registers_flag_type_and_admin_pages():
    app = make_app()
    with app.app_context():
        chal_ids = make_challenges(app, 1)
        admin = login_as_user(app, name="admin")
        types = admin.get("/api/v1/flags/types").get_json()["data"]
        assert "honeypot" in types
        assert admin.get(types["honeypot"]["templates"]["create"]).status_code == 200

        set_config("ai_guard_webhook_url", "")
        for path in (
            "/admin/ai_guard",
            "/admin/ai_guard/events",
            "/admin/ai_guard/honeypots",
            "/admin/ai_guard/settings",
            "/admin/users",
            "/plugins/ai_guard/assets/admin.js",
            "/plugins/ai_guard/assets/notice.js",
        ):
            r = admin.get(path)
            assert r.status_code == 200, path
        assert "AI Guard" in admin.get("/admin/ai_guard").get_data(as_text=True)
        settings_page = admin.get("/admin/ai_guard/settings").get_data(as_text=True)
        assert (
            'name="threshold"' in settings_page and 'name="auto_hide"' in settings_page
        )

        # honeypot can be created from the plugin page
        with admin.session_transaction() as sess:
            nonce = sess["nonce"]
        r = admin.post(
            "/admin/ai_guard/honeypots",
            data={
                "nonce": nonce,
                "challenge_id": chal_ids[0],
                "content": "flag{ai_only}",
                "data": "",
            },
        )
        assert r.status_code == 302
        page = admin.get("/admin/ai_guard/honeypots").get_data(as_text=True)
        assert "flag{ai_only}" in page

        # participants can not reach admin pages
        register_user(app)
        user = login_as_user(app)
        assert user.get("/admin/ai_guard").status_code in (302, 403)
        assert user.get(
            "/admin/ai_guard/api/scores", headers={"Accept": "application/json"}
        ).status_code in (302, 403)
    destroy_ctfd(app)


def test_fast_delta_signal():
    app = make_app()
    with app.app_context():
        chal_ids = make_challenges(app, 4)
        register_user(app)
        client = login_as_user(app)
        with freeze_time("2026-10-21 12:00:00") as frozen:
            assert submit(client, chal_ids[0], "flag{0}") == "correct"
            assert events() == []

            frozen.tick(10)  # < 15s critical
            assert submit(client, chal_ids[1], "flag{1}") == "correct"
            (event,) = events("fast_delta")
            assert event.weight == 3.0
            assert state_for(user_id=2).score == 3.0

            frozen.tick(40)  # < 60s
            assert submit(client, chal_ids[2], "flag{2}") == "correct"
            assert events("fast_delta")[-1].weight == 1.5
            assert state_for(user_id=2).score == 4.5

            frozen.tick(600)  # normal pace
            assert submit(client, chal_ids[3], "flag{3}") == "correct"
            assert len(events("fast_delta")) == 2

            # wrong flags never count
            assert submit(client, chal_ids[0], "nope") == "already_solved"
        assert state_for(user_id=2).score == 4.5
        assert Users.query.filter_by(id=2).first().hidden is False
    destroy_ctfd(app)


def test_burst_signal_counts_whole_team_once():
    app = make_app(user_mode="teams")
    with app.app_context():
        set_config("ai_guard_delta_weight", "0")
        set_config("ai_guard_delta_critical_weight", "0")
        chal_ids = make_challenges(app, 8)
        team = gen_team(app.db, member_count=4)
        team_id = team.id
        clients = [login_as_user(app, name=m.name) for m in team.members]
        with freeze_time("2026-10-21 12:00:00") as frozen:
            for i in range(4):
                assert submit(clients[i], chal_ids[i], f"flag{{{i}}}") == "correct"
                frozen.tick(30)
            assert events("burst") == []
            assert submit(clients[0], chal_ids[4], "flag{4}") == "correct"
            (burst,) = events("burst")
            assert burst.details_dict["solves"] == 5
            assert len(burst.details_dict["user_ids"]) == 4
            assert state_for(team_id=team_id).score == 3.0

            # the next solve inside the same window does not re-use already counted solves
            frozen.tick(30)
            assert submit(clients[1], chal_ids[5], "flag{5}") == "correct"
            assert len(events("burst")) == 1
    destroy_ctfd(app)


def test_honeypot_then_fast_solve_hides_user_and_notifies():
    app = make_app()
    sent = []
    with app.app_context():
        chal_ids = make_challenges(app, 3)
        gen_flag(
            app.db, challenge_id=chal_ids[0], content="flag{llm_trap}", type="honeypot"
        )
        set_config("ai_guard_webhook_url", "https://hooks.example.test/x")

        original_post, original_thread = notify._post, notify.threading.Thread

        class SyncThread:
            def __init__(self, target, args, daemon=None):
                self.target, self.args = target, args

            def start(self):
                self.target(*self.args)

        notify._post = lambda url, payload: sent.append((url, payload))
        notify.threading.Thread = SyncThread
        try:
            register_user(app)
            client = login_as_user(app)
            with freeze_time("2026-10-21 12:00:00") as frozen:
                # honeypot is a valid solution
                assert submit(client, chal_ids[0], "flag{llm_trap}") == "correct"
                (hp,) = events("honeypot")
                assert hp.weight == 6.0
                assert state_for(user_id=2).score == 6.0
                assert Users.query.filter_by(id=2).first().hidden is False
                assert len(sent) == 1 and "honeypot" in sent[0][1]["text"]

                frozen.tick(30)
                assert submit(client, chal_ids[1], "flag{1}") == "correct"
        finally:
            notify._post, notify.threading.Thread = original_post, original_thread

        state = state_for(user_id=2)
        assert state.score == 7.5
        assert state.auto_hidden is True
        assert Users.query.filter_by(id=2).first().hidden is True
        assert len(events("auto_hide")) == 1
        assert AIGuardNotice.query.filter_by(user_id=2).count() == 1
        assert "hidden from the scoreboard" in sent[-1][1]["text"]

        # the participant sees the notice once, the banner stays while hidden
        data = client.get("/ai_guard/api/notice").get_json()["data"]
        assert data["hidden"] is True
        (notice,) = data["notices"]
        assert notice["title"] == config.DEFAULT_NOTICE_TITLE
        assert (
            client.post(
                f"/ai_guard/api/notice/{notice['id']}/read", json={}
            ).status_code
            == 200
        )
        data = client.get("/ai_guard/api/notice").get_json()["data"]
        assert data["hidden"] is True and data["notices"] == []

        # hidden users disappear from the public scoreboard
        standings = client.get("/api/v1/scoreboard").get_json()["data"]
        assert all(s["account_id"] != 2 for s in standings)

        # admins see the alerts
        admin = login_as_user(app, name="admin")
        alerts = admin.get("/admin/ai_guard/api/alerts?after=0").get_json()
        assert alerts["unacked"] == 3
        assert [a["kind"] for a in alerts["data"]] == [
            "honeypot",
            "fast_delta",
            "auto_hide",
        ]
        scores = admin.get("/admin/ai_guard/api/scores").get_json()
        assert (
            scores["data"]["2"]["score"] == 7.5 and scores["data"]["2"]["auto_hidden"]
        )
        assert admin.get("/admin/ai_guard/account/2").status_code == 200
        r = admin.post("/admin/ai_guard/api/alerts/ack", json={})
        assert r.get_json()["unacked"] == 0
    destroy_ctfd(app)


def test_honeypot_counts_once_and_on_already_solved():
    app = make_app()
    with app.app_context():
        set_config("ai_guard_honeypot_weight", "2")
        chal_ids = make_challenges(app, 2)
        gen_flag(
            app.db,
            challenge_id=chal_ids[0],
            content="FLAG{Hidden}",
            type="honeypot",
            data="case_insensitive",
        )
        register_user(app)
        client = login_as_user(app)
        assert submit(client, chal_ids[0], "flag{0}") == "correct"
        assert submit(client, chal_ids[0], "flag{hidden}") == "already_solved"
        assert submit(client, chal_ids[0], "flag{HIDDEN}") == "already_solved"
        assert len(events("honeypot")) == 1
        assert state_for(user_id=2).score == 2.0
    destroy_ctfd(app)


def test_team_hidden_instantly_and_admin_restores():
    app = make_app(user_mode="teams")
    with app.app_context():
        set_config("ai_guard_honeypot_weight", "8")
        chal_ids = make_challenges(app, 3)
        gen_flag(
            app.db, challenge_id=chal_ids[1], content="flag{trap}", type="honeypot"
        )
        team = gen_team(app.db, member_count=2)
        team_id = team.id
        members = [m.name for m in team.members]
        first = login_as_user(app, name=members[0])
        second = login_as_user(app, name=members[1])

        assert submit(first, chal_ids[1], "flag{trap}") == "correct"
        assert Teams.query.filter_by(id=team_id).first().hidden is True
        # every team member gets the notice
        for client in (first, second):
            data = client.get("/ai_guard/api/notice").get_json()["data"]
            assert data["hidden"] is True and len(data["notices"]) == 1

        admin = login_as_user(app, name="admin")
        with admin.session_transaction() as sess:
            nonce = sess["nonce"]
        assert admin.get("/admin/teams").status_code == 200
        assert admin.get(f"/admin/teams/{team_id}").status_code == 200
        r = admin.post(
            f"/admin/ai_guard/account/{team_id}/action",
            data={"nonce": nonce, "action": "unhide", "reset": "y"},
        )
        assert r.status_code == 302
        state = state_for(team_id=team_id)
        assert state.score == 0 and state.auto_hidden is False
        assert Teams.query.filter_by(id=team_id).first().hidden is False
        assert first.get("/ai_guard/api/notice").get_json()["data"]["hidden"] is False

        # trusted accounts are ignored completely
        admin.post(
            f"/admin/ai_guard/account/{team_id}/action",
            data={"nonce": nonce, "action": "whitelist"},
        )
        gen_flag(
            app.db, challenge_id=chal_ids[2], content="flag{trap2}", type="honeypot"
        )
        assert submit(second, chal_ids[2], "flag{trap2}") == "correct"
        assert state_for(team_id=team_id).score == 0
        assert Teams.query.filter_by(id=team_id).first().hidden is False
    destroy_ctfd(app)


def test_settings_page_and_disabled_detection():
    app = make_app()
    with app.app_context():
        admin = login_as_user(app, name="admin")
        with admin.session_transaction() as sess:
            nonce = sess["nonce"]
        form = {
            name: str(default)
            for name, (kind, default, _l, _h) in config.SETTINGS.items()
            if kind is not bool
        }
        form.update(
            {"nonce": nonce, "threshold": "5,5", "burst_count": "3", "auto_hide": "y"}
        )
        assert admin.post("/admin/ai_guard/settings", data=form).status_code == 302
        assert config.get("threshold") == 5.5
        assert config.get("burst_count") == 3
        assert config.get("auto_hide") is True
        assert config.get("enabled") is False  # checkbox not sent

        chal_ids = make_challenges(app, 2)
        register_user(app)
        client = login_as_user(app)
        with freeze_time("2026-10-21 12:00:00") as frozen:
            submit(client, chal_ids[0], "flag{0}")
            frozen.tick(1)
            submit(client, chal_ids[1], "flag{1}")
        assert events() == []
    destroy_ctfd(app)


def test_admin_submissions_are_ignored():
    app = make_app()
    with app.app_context():
        chal_ids = make_challenges(app, 2)
        admin = login_as_user(app, name="admin")
        gen_flag(
            app.db, challenge_id=chal_ids[0], content="flag{trap}", type="honeypot"
        )
        submit(admin, chal_ids[0], "flag{trap}")
        assert events() == []
        assert AIGuardState.query.count() == 0
        assert Solves.query.count() == 1
    destroy_ctfd(app)


def test_api_token_submission_signal():
    app = make_app()
    with app.app_context():
        # isolate the signal: both solves below happen within milliseconds
        set_config("ai_guard_delta_weight", "0")
        set_config("ai_guard_delta_critical_weight", "0")
        chal_ids = make_challenges(app, 2)
        register_user(app)
        user = Users.query.filter_by(name="user").first()
        user_id = user.id
        token = generate_user_token(user).value

        # a browser session does not trigger the signal
        browser = login_as_user(app)
        assert submit(browser, chal_ids[0], "flag{0}") == "correct"
        assert events("api_token") == []

        with app.test_client() as client:
            r = client.post(
                "/api/v1/challenges/attempt",
                json={"challenge_id": chal_ids[1], "submission": "flag{1}"},
                headers={
                    "Authorization": f"Token {token}",
                    "User-Agent": "python-requests/2.32.4",
                },
            )
            assert r.get_json()["data"]["status"] == "correct"
            # wrong flags sent with a token are not counted
            client.post(
                "/api/v1/challenges/attempt",
                json={"challenge_id": chal_ids[0], "submission": "nope"},
                headers={"Authorization": f"Token {token}"},
            )
        (event,) = events("api_token")
        assert event.weight == 1.5
        assert event.challenge_id == chal_ids[1]
        assert event.details_dict["user_agent"] == "python-requests/2.32.4"
        assert state_for(user_id=user_id).score == 1.5
    destroy_ctfd(app)


def test_quick_solve_after_first_view():
    app = make_app(user_mode="teams")
    with app.app_context():
        # isolate the signal
        set_config("ai_guard_delta_weight", "0")
        set_config("ai_guard_delta_critical_weight", "0")
        set_config("ai_guard_burst_weight", "0")
        chal_ids = make_challenges(app, 4)
        cheap_id = gen_challenge(app.db, name="sanity", value=10).id
        gen_flag(app.db, challenge_id=cheap_id, content="flag{sanity}")
        team = gen_team(app.db, member_count=2)
        team_id = team.id
        opener_name, solver_name = (m.name for m in team.members)
        opener = login_as_user(app, name=opener_name)
        solver = login_as_user(app, name=solver_name)

        with freeze_time("2026-10-21 12:00:00") as frozen:
            # views are recorded even while the analysis is disabled
            set_config("ai_guard_enabled", "false")
            assert opener.get(f"/api/v1/challenges/{chal_ids[0]}").status_code == 200
            set_config("ai_guard_enabled", "true")
            frozen.tick(20)
            # a later view by a teammate does not move the first one
            assert solver.get(f"/api/v1/challenges/{chal_ids[0]}").status_code == 200
            assert AIGuardView.query.filter_by(team_id=team_id).count() == 1
            assert submit(solver, chal_ids[0], "flag{0}") == "correct"
            (event,) = events("quick_solve")
            assert event.weight == 3.0  # 20s < 30s critical
            assert opener_name in event.details_dict["summary"]

            opener.get(f"/api/v1/challenges/{chal_ids[1]}")
            frozen.tick(90)
            assert submit(solver, chal_ids[1], "flag{1}") == "correct"
            assert events("quick_solve")[-1].weight == 1.5  # 90s < 120s

            opener.get(f"/api/v1/challenges/{chal_ids[2]}")
            frozen.tick(600)
            assert submit(solver, chal_ids[2], "flag{2}") == "correct"
            # never opened -> nothing to measure
            assert submit(solver, chal_ids[3], "flag{3}") == "correct"
            # cheap challenges (sanity checks) are ignored
            opener.get(f"/api/v1/challenges/{cheap_id}")
            frozen.tick(5)
            assert submit(opener, cheap_id, "flag{sanity}") == "correct"

        assert len(events("quick_solve")) == 2
        assert state_for(team_id=team_id).score == 4.5

        admin = login_as_user(app, name="admin")
        page = admin.get(f"/admin/ai_guard/account/{team_id}").get_data(as_text=True)
        assert "Quick solve after opening" in page
        # admins opening challenges are not recorded
        admin.get(f"/api/v1/challenges/{chal_ids[3]}")
        assert AIGuardView.query.count() == 4
    destroy_ctfd(app)


def test_wall_of_shame():
    app = make_app(user_mode="teams")
    with app.app_context():
        chal_ids = make_challenges(app, 4)
        shamed = gen_team(
            app.db, name="Cheaters", email="c@examplectf.com", member_count=2
        )
        honest = gen_team(
            app.db, name="Honest", email="h@examplectf.com", member_count=1
        )
        shamed_id = shamed.id
        cheater_name = shamed.members[0].name
        cheater_id = shamed.members[0].id
        player_name = honest.members[0].name
        cheater = login_as_user(app, name=cheater_name)
        player = login_as_user(app, name=player_name)
        admin = login_as_user(app, name="admin")
        with admin.session_transaction() as sess:
            nonce = sess["nonce"]

        assert submit(cheater, chal_ids[0], "flag{0}") == "correct"

        # the page is not published yet
        with app.test_client() as anonymous:
            assert anonymous.get("/wall-of-shame").status_code == 404

        r = admin.post(
            f"/admin/ai_guard/account/{shamed_id}/action",
            data={"nonce": nonce, "action": "shame", "comment": "LLM agent detected"},
        )
        assert r.status_code == 302
        assert Teams.query.filter_by(id=shamed_id).first().hidden is True
        # shaming twice does not create a duplicate
        admin.post(
            f"/admin/ai_guard/account/{shamed_id}/action",
            data={"nonce": nonce, "action": "shame"},
        )
        assert AIGuardShame.query.count() == 1

        # submissions of the shamed team are blocked, with a session or a token
        r = cheater.post(
            "/api/v1/challenges/attempt",
            json={"challenge_id": chal_ids[1], "submission": "flag{1}"},
        )
        assert r.status_code == 403
        assert r.get_json()["data"]["status"] == "paused"
        assert "wall of shame" in r.get_json()["data"]["message"]
        token = generate_user_token(Users.query.filter_by(id=cheater_id).first()).value
        with app.test_client() as script:
            r = script.post(
                "/api/v1/challenges/attempt",
                json={"challenge_id": chal_ids[1], "submission": "flag{1}"},
                headers={"Authorization": f"Token {token}"},
            )
            assert r.status_code == 403
        assert Solves.query.filter_by(team_id=shamed_id).count() == 1
        # other teams are not affected
        assert submit(player, chal_ids[1], "flag{1}") == "correct"

        # the team members are told about it
        data = cheater.get("/ai_guard/api/notice").get_json()["data"]
        assert data["shamed"] is True and data["hidden"] is True
        assert "wall of shame" in data["banner"]
        assert data["notices"][0]["title"] == config.DEFAULT_SHAME_NOTICE_TITLE

        # admins preview the unpublished page
        page = admin.get("/wall-of-shame").get_data(as_text=True)
        assert "Cheaters" in page and "not published" in page

        assert (
            admin.post(
                "/admin/ai_guard/shame/settings",
                data={"nonce": nonce, "action": "enable"},
            ).status_code
            == 302
        )
        # saving the general settings form keeps the page published
        form = {
            name: str(default)
            for name, (kind, default, _l, _h) in config.SETTINGS.items()
            if kind is not bool
        }
        form.update({"nonce": nonce, "enabled": "y", "auto_hide": "y"})
        admin.post("/admin/ai_guard/settings", data=form)
        assert config.get("shame_enabled") is True

        with app.test_client() as anonymous:
            r = anonymous.get("/wall-of-shame")
            assert r.status_code == 200
            page = r.get_data(as_text=True)
            assert "Cheaters" in page and "LLM agent detected" in page
            assert "Honest" not in page
            assert config.DEFAULT_SHAME_TITLE in page

        for path in (
            "/admin/ai_guard/shame",
            "/admin/ai_guard",
            f"/admin/ai_guard/account/{shamed_id}",
        ):
            assert admin.get(path).status_code == 200, path
        assert "wall of shame" in admin.get("/admin/ai_guard").get_data(as_text=True)
        scores = admin.get("/admin/ai_guard/api/scores").get_json()["data"]
        assert scores[str(shamed_id)]["shamed"] is True

        # a shamed team can not simply be restored to the scoreboard
        admin.post(
            f"/admin/ai_guard/account/{shamed_id}/action",
            data={"nonce": nonce, "action": "unhide", "reset": "y"},
        )
        assert Teams.query.filter_by(id=shamed_id).first().hidden is True

        # removing from the wall re-enables submissions, the team stays hidden
        admin.post(
            f"/admin/ai_guard/account/{shamed_id}/action",
            data={"nonce": nonce, "action": "unshame"},
        )
        assert AIGuardShame.query.count() == 0
        assert submit(cheater, chal_ids[1], "flag{1}") == "correct"
        assert Teams.query.filter_by(id=shamed_id).first().hidden is True
        with app.test_client() as anonymous:
            assert "Cheaters" not in anonymous.get("/wall-of-shame").get_data(
                as_text=True
            )
        kinds_logged = [e.kind for e in events() if e.team_id == shamed_id]
        assert "shame" in kinds_logged and "unshame" in kinds_logged
    destroy_ctfd(app)


def test_custom_participant_texts():
    app = make_app()
    with app.app_context():
        set_config("ai_guard_honeypot_weight", "8")
        chal_ids = make_challenges(app, 2)
        gen_flag(
            app.db, challenge_id=chal_ids[0], content="flag{trap}", type="honeypot"
        )
        register_user(app)
        client = login_as_user(app)
        admin = login_as_user(app, name="admin")
        with admin.session_transaction() as sess:
            nonce = sess["nonce"]

        # defaults are worded for the user mode
        assert config.text("shame_blocked", False) == (
            "Flag submission is disabled: your account is on the wall of shame."
        )
        settings_page = admin.get("/admin/ai_guard/settings").get_data(as_text=True)
        assert 'name="notice_banner"' in settings_page
        assert config.text("notice_banner", False) in settings_page

        form = {
            name: str(default)
            for name, (kind, default, _l, _h) in config.SETTINGS.items()
            if kind is not bool
        }
        form.update(
            {
                "nonce": nonce,
                "enabled": "y",
                "auto_hide": "y",
                "honeypot_weight": "8",
                "notice_title": "Аккаунт скрыт",
                "notice_text": "Откройте тикет у организаторов.",
                "notice_banner": "Аккаунт скрыт из рейтинга, откройте тикет",
            }
        )
        admin.post("/admin/ai_guard/settings", data=form)

        admin.post(
            "/admin/ai_guard/shame/settings",
            data={"nonce": nonce, "action": "texts", "shame_title": "Доска позора"},
        )
        # a form with only some of the texts keeps the others
        admin.post(
            "/admin/ai_guard/shame/settings",
            data={
                "nonce": nonce,
                "action": "texts",
                "shame_notice_title": "Вы на доске позора",
                "shame_notice_text": "Решение организаторов.",
                "shame_blocked": "Сдача флагов заблокирована",
            },
        )
        assert config.get("shame_title") == "Доска позора"
        shame_page = admin.get("/admin/ai_guard/shame").get_data(as_text=True)
        assert (
            'name="shame_blocked"' in shame_page
            and "Сдача флагов заблокирована" in shame_page
        )

        # auto-hide uses the custom notice and banner
        assert submit(client, chal_ids[0], "flag{trap}") == "correct"
        data = client.get("/ai_guard/api/notice").get_json()["data"]
        assert data["banner"] == "Аккаунт скрыт из рейтинга, откройте тикет"
        (notice,) = data["notices"]
        assert notice["title"] == "Аккаунт скрыт"
        assert notice["content"] == "Откройте тикет у организаторов."

        # the wall of shame uses the custom notice, blocked message and page title
        admin.post(
            "/admin/ai_guard/account/2/action", data={"nonce": nonce, "action": "shame"}
        )
        r = client.post(
            "/api/v1/challenges/attempt",
            json={"challenge_id": chal_ids[1], "submission": "flag{1}"},
        )
        assert r.status_code == 403
        assert r.get_json()["data"]["message"] == "Сдача флагов заблокирована"
        data = client.get("/ai_guard/api/notice").get_json()["data"]
        assert data["banner"] == "Сдача флагов заблокирована"
        assert data["notices"][-1]["title"] == "Вы на доске позора"
        assert data["notices"][-1]["content"] == "Решение организаторов."
        assert "Доска позора" in admin.get("/wall-of-shame").get_data(as_text=True)

        # an emptied field falls back to the default text
        admin.post(
            "/admin/ai_guard/shame/settings",
            data={"nonce": nonce, "action": "texts", "shame_blocked": ""},
        )
        r = client.post(
            "/api/v1/challenges/attempt",
            json={"challenge_id": chal_ids[1], "submission": "flag{1}"},
        )
        assert r.get_json()["data"]["message"] == config.text("shame_blocked", False)
        assert "your account" in r.get_json()["data"]["message"]
    destroy_ctfd(app)
