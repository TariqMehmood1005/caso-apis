from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from . import views

app_name = 'CoinsSellingPlatformApp'

urlpatterns = [
    ###################################### FRONTEND MANAGEMENT SYSTEM ##################################################

    # path('global-chat/', views.global_chat, name='global_chat'),
    # path('terms_and_conditions/', views.terms_and_conditions, name='terms_and_conditions'),
    # path('waitlist/', views.waitlist, name='waitlist'),
    # path('join_waitlist/', views.join_waitlist, name='join_waitlist'),

    # # Game Routes
    # # path('top-rated-games/', views.top_rated_games, name='top_rated_games'),
    # path('terms-and-conditions/', views.terms_and_conditions, name='terms_and_conditions'),
    # path('top-rated-games/play-game/<str:game_name>/', views.play_games, name='play_games'),

    # # path('upcoming-games/<str:game_name>/', views.upcoming_games, name='upcoming_games'),

    # path('reviews-and-rating/', views.reviews_and_rating, name='reviews_and_rating'),
    # path('reviews-and-rating/full-review/<str:review_name>/', views.full_review, name='full_review'),
    # path('upgrade-your-plan/', views.upgrade_your_plan, name='upgrade_your_plan'),
    # path('privacy-policy/', views.privacy_policy, name='privacy_policy'),

    # # Routes by Mudassar Sattar
    # path('view-trending-games/', views.view_trending_games, name='view_trending_games'),
    # path('view-popular-games/', views.view_popular_games, name='view_popular_games'),
    # path('view-game-history/', views.view_game_history, name='view_game_history'),
    # path('view-all-games/', views.view_all_games, name='view_all_games'),
    # path('faqs/', views.faqs, name='faqs'),
    # path('view-over-view/', views.view_over_view, name='view_over_view'),

    # # User Dashboard Routes
    # path('dashboards/user/', views.user_index, name='user_dashboard_index'),

    # # User Dashboard Routes
    # path('dashboards/user/user-detail', views.user_detail_index, name='user_detail'),
    # path('dashboards/user/game-detail', views.game_detail_index, name='game_detail_index'),
    # path('dashboards/user/wallet', views.wallet, name='wallet'),
    # path('dashboards/user/wallet-history', views.wallet_history, name='wallet-history'),
    # path('dashboards/user/add-payment', views.add_payment, name='add_payment'),
    # path('dashboards/user/payment-method', views.payment_method, name='payment_method'),

    # # Scoreboard Routes by Mudassar Sattar
    # path('score-board/', views.score_board, name='score_board'),
    # path('redeem/', views.redeem, name='redeem'),
    # path('transfer/', views.transfer, name='transfer'),

    # ## ADMIN DASHBOARD URLS
    # path('dashboards/admin/', views.admin_index, name='admin_dashboard_index'),
    # path('dashboards/admin/login/', views.admin_login, name='admin_login'),
    # path('dashboards/admin/login-process/', views.admin_login_process, name='admin_login_process'),
    # path('dashboards/admin/logout/', views.admin_logout, name='admin_logout'),
    # path('dashboards/admin/user-profile-regular/', views.user_profile_regular, name='user_profile_regular'),
    # path('dashboards/admin/update-user-phone/', views.update_user_phone, name='update_user_phone'),
    # path('dashboards/admin/request-password/', views.request_password, name='request_password'),
    # path('dashboards/admin/confirm-requested-password/', views.confirm_requested_password, name='confirm_requested_password'),
    # path('dashboards/admin/update-user-personal-information/', views.update_user_personal_information, name='update_user_personal_information'),

    # ##
    # path('dashboards/admin/players/', views.my_players, name='my_players'),
    # path('dashboards/admin/players/block/<str:player_username>/', views.block_my_players, name='block_my_players'),
    # path('dashboards/admin/players/delete/<str:player_username>/', views.delete_my_players, name='delete_my_players'),
    # path('dashboards/admin/players/change-game-player-password/', views.change_game_player_password, name='change_game_player_password'),
    # path('dashboards/admin/players/add/', views.add_player_data, name='add_player_data'),

    # ##
    # path('dashboards/admin/games/', views.my_games, name='my_games'),
    # path('dashboards/admin/games/delete/<str:game_id>/', views.delete_my_game, name='delete_my_game'),
    # path('dashboards/admin/games/block/<str:game_id>/', views.block_my_games, name='block_my_games'),
    # path('dashboards/admin/games/is-free/<str:game_id>/', views.is_free_game_admin, name='is_free_game_admin'),
    # path('dashboards/admin/games/upcoming-status/<str:game_id>/', views.upcoming_status_game_admin, name='upcoming_status_game_admin'),
    # path('dashboards/admin/games/is-trending/<str:game_id>/', views.is_trending_game_admin, name='is_trending_game_admin'),
    # path('dashboards/admin/games/add/', views.add_game_data, name='add_game_data'),
    # path('dashboards/admin/games/update/<str:game_id>/', views.update_my_game, name='update_my_game'),

    # path('dashboards/admin/agent-chat/', views.my_agent_chat, name='my_agent_chat'),
    # ## ADMIN DASHBOARD URLS

    # ###################################### FRONTEND MANAGEMENT SYSTEM ##################################################







    ###################################### APIS MANAGEMENT SYSTEM ######################################################
    # Token Management
    path('api/v1/token/', obtain_auth_token, name='token_obtain_pair'),
    path('api/v1/token/refresh/', obtain_auth_token, name='token_refresh'),
    # Token Management


    # Authorization & Authentication
    path('api/v1/check-email/', views.check_email, name='check_email'),##
    path('api/v1/sign-up/', views.sign_up_api_view, name='sign_up'),##
    path('api/v1/get-all-users/', views.get_all_users, name='get_all_users'),##
    path('api/v1/verify-otp-with-user-signup/', views.verify_otp_with_user_signup, name='verify_otp_with_user_signup'), ##
    
    path('api/v1/update-user-with-licensees-and-increases-xp-levels/',
         views.update_user_with_licensees_and_increases_xp_levels,
         name='update_user_with_licensees_and_increases_xp_levels'),
    path('api/v1/phone-verification-and-get-free-xp/', views.phone_verification_and_get_free_xp, name='phone_verification_and_get_free_xp'),
    path('api/v1/update-user-personal-information-api/', views.update_user_personal_information_api, name='update_user_personal_information_api'),
    path('api/v1/update-user-documents/', views.update_user_documents, name='update_user_documents'),
    path('api/v1/login/', views.login_api_view, name='login'),
    path('api/v1/verify-otp/', views.verify_otp, name='verify_otp'),
    path('api/v1/refresh-otp/', views.refresh_otp, name='refresh_otp'),
    path('api/v1/request-reset-password/', views.request_reset_password, name='request_reset_password'),
    path('api/v1/confirm-reset-password/', views.confirm_reset_password, name='confirm_reset_password'),
    path('api/v1/verify-email/',views.verify_email, name='verify_email'),
    path('api/v1/de-activate-user/', views.de_activate_user, name='de_activate_user'), # Block User
    path('api/v1/activate-user/', views.activate_user, name='activate_user'), # Un-block User
    path('api/v1/upload-profiles-and-banners/', views.upload_profiles_and_banners, name='upload_profiles_and_banners'),
    path('api/v1/profile/', views.profile, name='profile'),
    # Authorization & Authentication

    # Chat Management System
    path('api/v1/chat/send-chat-to-agent/', views.send_chat_to_agent, name='send_chat_to_agent'),
    path('api/v1/chat/send-chat-to-user/', views.send_chat_to_user, name='send_chat_to_user'),
    path('api/v1/chat/activate-user-agent-chat/', views.activate_user_agent_chat, name='activate_user_agent_chat'),
    path('api/v1/chat/de-activate-user-agent-chat/', views.de_activate_user_agent_chat, name='de_activate_user_agent_chat'),
    path('api/v1/chat/is-agent-alive/', views.is_agent_alive, name='is_agent_alive'),
    path('api/v1/chat/is-user-alive/', views.is_user_alive, name='is_user_alive'),
    path('api/v1/chat/get-agent-chat-history/', views.get_agent_chat_history, name='get_agent_chat_history'),
    path('api/v1/chat/get-global-chat-history/', views.get_global_chat_history, name='get_global_chat_history'),
    path('api/v1/chat/get-global-chats/', views.get_global_chats, name='get_global_chats'),
    path('api/v1/chat/send-message-to-global-chat/', views.send_message_to_global_chat, name='send_message_to_global_chat'),
    path('api/v1/chat/get_admin_and_agent_chat_history/',views.get_admin_and_agent_chat_history,name='get_admin_and_agent_chat_history'),
    path('api/v1/chat/get-agent-and-user-chat-history/',views.get_agent_and_user_chat_history,name='get_agent_and_user_chat_history'),
    # Chat Management System

    # Reviews Management System
    path('api/v1/reviews/get-reviews/', views.get_reviews, name='get_reviews'),  # (limit = 10)
    path('api/v1/reviews/post-game-review/', views.post_game_review, name='post_game_review'),
    path('api/v1/reviews/delete-game-review/', views.delete_game_review, name='delete_game_review'), # (user_id, game_id, review_id)
    path('api/v1/reviews/get-game-rating/', views.get_game_rating, name='get_game_rating'),  # (game_id)
    path('api/v1/reviews/post-admin-reply/', views.post_admin_reply, name='post_admin_reply'),
    path('api/v1/reviews/get-admin-replies/', views.get_admin_replies, name='get_admin_replies'),
    path('api/v1/reviews/update-admin-reply/', views.update_admin_reply, name='update_admin_reply'),  # (admin_reply_id_pk)
    path('api/v1/reviews/delete-admin-reply/', views.delete_admin_reply, name='delete_admin_reply'),  # (admin_reply_id_pk)
    path('api/v1/reviews/update-game-review-ratings/', views.update_game_review_ratings, name='update_game_review_ratings'),  # (admin_reply_id_pk)
    path('api/v1/reviews/update-admin-reply-ratings/', views.update_admin_reply_ratings, name='update_admin_reply_ratings'),  # (admin_reply_id_pk)
    # Reviews Management System

    # Games Management System
    ##
    path('api/v1/games/get-games-data/', views.get_games_data, name='get_games_data'),
    ##
    path('api/v1/games/add-game/', views.add_game, name='add_game'),
    path('api/v1/games/get-game-by-name/<str:game_name>/', views.get_game_by_name, name='get_game_by_name'),
    path('api/v1/games/get-available-games/', views.get_available_games, name='get_available_games'),  # limit=10
    path('api/v1/games/get-available-games-by-admin-and-agent-tokens/', views.get_available_games_by_admin_and_agent_tokens, name='get_available_games_by_admin_and_agent_tokens'),  # limit=10
    path('api/v1/games/get-all-free-games/', views.get_all_free_games, name='get_all_free_games'),  # limit=10
    path('api/v1/games/get-trending-games/', views.get_trending_games, name='get_trending_games'),  # limit=10
    path('api/v1/games/get-upcoming-games/', views.get_upcoming_games, name='get_upcoming_games'),  # limit=10
    path('api/v1/games/update-game/', views.update_game, name='update_game'),  # (game_id)
    path('api/v1/games/delete-game/', views.delete_game, name='delete_game'),  # (game_id)
    path('api/v1/games/redeem-game-player-scores-to-wallet/', views.redeem_game_player_scores_to_wallet, name='redeem_game_player_scores_to_wallet'),  # (game_id)
    path('api/v1/games/get-game-transaction-history/', views.get_game_transaction_history, name='get_game_transaction_history'),  # (game_id, limit=10)
    path('api/v1/games/get-game-player-by-username/', views.get_game_player_by_username, name='get_game_player_by_username'),  # (game_id, username)
    path('api/v1/games/game-to-game-redemption/', views.game_to_game_redemption, name='game_to_game_redemption'),  # (game_id, username)
    path('api/v1/games/get-all-games-under-user-freeplays/', views.get_all_games_under_user_freeplays, name='get_all_games_under_user_freeplays'),  # (game_id, username)
    ## Games Management System

    ## Admin Game Panel Management System
    path('api/v1/admin-game-panel/create-player/', views.create_player_by_admin, name='create_player_by_admin'),  # Create a new player
    path('api/v1/admin-game-panel/reset-game-password/', views.reset_game_password, name='reset_game_password'),  # reset_game_password
    path('api/v1/admin-game-panel/get-panel-scores/', views.get_panel_scores, name='get_panel_scores'),  # Get panel scores (limit=10, admin only)
    path('api/v1/admin-game-panel/redeem-score-from-game/', views.redeem_score_from_game, name='redeem_score_from_game'),  # Redeem score (game_id)
    path('api/v1/admin-game-panel/get-all-game-accounts/', views.get_all_games_accounts, name='get_all_games_accounts'),  # Get game score (game_id)
    path('api/v1/admin-game-panel/get-all-my-created-players/', views.get_all_my_created_players_by_admin, name='get_all_my_created_players_by_admin'),
    path('api/v1/admin-game-panel/get-all-my-created-games/', views.get_all_my_created_games_by_admin, name='get_all_my_created_games_by_admin'),
    path('api/v1/admin-game-panel/get-player-score/', views.get_player_score, name='get_player_score'),
    path('api/v1/admin-game-panel/get-game-stats/', views.get_game_stats, name='get_game_stats'),
    path('api/v1/admin-game-panel/block-player/', views.block_player, name='block_player'),
    path('api/v1/admin-game-panel/block-game/', views.block_game, name='block_game'),
    path('api/v1/admin-game-panel/is-free-game/', views.is_free_game, name='is_free_game'),
    path('api/v1/admin-game-panel/upcoming/', views.upcoming_status, name='upcoming_status'),
    path('api/v1/admin-game-panel/trending/', views.is_trending, name='is_trending'),
    path('api/v1/admin-game-panel/delete-player/', views.delete_player, name='delete_player'),
    path('api/v1/admin-game-panel/delete-game/', views.delete_game, name='delete_game'),
    path('api/v1/admin-game-panel/update-game/', views.update_game_by_admin_agent, name='update_game_by_admin_agent'),
    path('api/v1/admin-game-panel/all-agent-user-chats/', views.all_agent_user_chats, name='all_agent_user_chats'),
    ## Admin Game Panel Management System


    ## Spin Wheel Management System
    path('api/v1/spin/get-spin-wheel/', views.get_spin_wheel, name='get_spin_wheel'),  # Create a new player
    path('api/v1/spin/spin-history/', views.spin_history, name='spin_history'),  # Create a new player
    ## Spin Wheel Management System


    ## Prize Management System
    path('api/v1/prizes/get-prizes/', views.get_prizes, name='get_prizes'),
    path('api/v1/prizes/create-prize/', views.create_prize, name='create_prize'),
    path('api/v1/prizes/get-prize-by-id/', views.get_prize_by_id, name='get_prize_by_id'),
    path('api/v1/prizes/update-prize/', views.update_prize, name='update_prize'),
    path('api/v1/prizes/delete-prize/', views.delete_prize, name='delete_prize'),
    ## Prize Management System


    ## Promo Code Management System
    path('api/v1/promo-code/get-promo-codes/', views.get_promo_codes, name='get_promo_codes'),
    path('api/v1/promo-code/create-promo-codes/', views.create_promo_code, name='create_promo_code'),
    path('api/v1/promo-code/verify-promo-code/', views.verify_promo_code, name='verify_promo_code'),
    path('api/v1/promo-code/get-promo-code/', views.get_promo_code_by_id, name='get_promo_code_by_id'),
    path('api/v1/promo-code/delete-promo-code/', views.delete_promo_code, name='delete_promo_code'),
    ## Promo Code Management System


    ## Level Management System
    path('api/v1/levels/get-levels/', views.get_levels, name='get_levels'),
    path('api/v1/levels/get-level/', views.get_level_by_id, name='get_level_by_id'),
    path('api/v1/levels/create-levels/', views.create_level, name='create_level'),
    path('api/v1/levels/delete-level/', views.delete_level, name='delete_level'),
    path('api/v1/levels/update-level/', views.update_level, name='update_level'),
    ## Level Management System


    ## Referral Management System
    path('api/v1/referral/create-referral-code/', views.create_referral_code, name='create_referral_code'),  # Endpoint for creating referral codes
    path('api/v1/referral/get-referral-codes/', views.get_referral_codes, name='get_referral_codes'),  # (player_username, all by limit=20)
    path('api/v1/referral/verify-referral-code/', views.verify_referral_code, name='verify_referral_code'),  # (referral_code)
    path('api/v1/referral/verify-referral-key-by-link/',views.verify_referral_key_by_link,name='verify_referral_key_by_link'),
    path('api/v1/referral/get-all-referrals-by-username/', views.get_all_referrals_by_username, name='get_all_referrals_by_username'),  # Get all referrals
    path('api/v1/referral/delete-all-referrals/', views.delete_all_referrals, name='delete_all_referrals'),  # Delete a referral by key
    path('api/v1/referral/delete-by-referral-key/', views.delete_referral_by_key, name='delete_referral_by_key'),  # Delete a specific referral
    ## Referral Management System


    ## Wallet Management System
    path('api/v1/wallet/payment/', views.handle_payment, name='handle_payment'),
    path('api/v1/wallet/get-user-account-wallet/', views.get_user_account_wallet, name='get_user_account_wallet'), # Get user wallet details
    path('api/v1/wallet/get-transaction-history/', views.get_transaction_history, name='get_transaction_history'), # Get wallet transaction history
    path('api/v1/wallet/pay-by-link/', views.pay_by_link, name='pay_by_link'),  # Generate payment link
    path('api/v1/wallet/verify-payment-by-order-id/', views.verify_payment_by_order_id, name='verify_payment_by_order_id'),  # Verify payment by ID
    path('api/v1/wallet/withdraw-money-from-user-account-wallet/', views.withdraw_money_from_user_account_wallet, name='withdraw_money_from_user_account_wallet'), # Admin: Remove money from wallet
    path('api/v1/wallet/deposit-money-to-user-account-wallet/', views.deposit_money_to_user_account_wallet, name='deposit_money_to_user_account_wallet'), # Admin: Remove money from wallet
    # path('api/v1/wallet/get-order-status/', views.get_order_status, name='get_order_status'),  # Check order status
    ## Wallet Management System


    ## Landing Page Data Management System
    path('api/v1/landing/data/', views.landing_page_data, name='landing_page_data'),
    ## Landing Page Data Management System


    ## Agent Panel Management System
    path('api/v1/agent-panel/create-player/', views.create_player_by_agent, name='create_player_by_agent'),
    path('api/v1/agent-panel/get-all-my-created-players/', views.get_all_my_created_players, name='get_all_my_created_players'),
    ## Agent Panel Management System

    ## User Management System
    path('api/v1/user-panel/create-player/', views.create_player_by_user, name='create_player_by_user'),
    path('api/v1/user-panel/get-all-game-accounts/', views.get_all_my_accounts, name='get_all_my_accounts'),
    path('api/v1/user-panel/update-score/', views.update_score, name='update_score'),
    ## User Management System

    ###################################### APIS MANAGEMENT SYSTEM ######################################################

# ]
# ## code by Hafiz
# from django.conf import settings
# from django.conf.urls.static import static

# # Serve media files in development mode
# if settings.DEBUG:
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)